import re
import asyncio
from fastapi import APIRouter
from models import CloudReq
from tools.utils import http_get, f, ok, err

router = APIRouter(tags=["analysis"])


def derive_name(target: str) -> str:
    n = re.sub(r'^https?://', '', target.strip().lower())
    n = re.sub(r'\.(com|org|net|io|co|uk|in|de|fr|jp|au|ca|br|ru|cn|me|app|dev|xyz).*$', '', n)
    return re.sub(r'[^a-z0-9\-]', '', n)


@router.post("/cloud")
async def cloud_exposure(req: CloudReq):
    name = derive_name(req.target)
    if not name:
        return err("Cannot derive company name from input")
    findings = []
    records = []

    variants = [name, f"{name}-assets", f"{name}-static", f"{name}-media",
                f"{name}-files", f"{name}-backup", f"{name}-data", f"{name}-dev",
                f"{name}-staging", f"{name}-prod", f"{name}-uploads",
                f"{name}-images", f"{name}-storage", f"www.{name}", f"{name}.com"]

    async def check_s3(bucket: str):
        r = await http_get(f"https://{bucket}.s3.amazonaws.com/", timeout=5, follow_redirects=False)
        return bucket, r["status"]

    async def check_azure(account: str):
        r = await http_get(f"https://{account}.blob.core.windows.net/$web/", timeout=5, follow_redirects=False)
        return account, r["status"]

    async def check_gcp(bucket: str):
        r = await http_get(f"https://storage.googleapis.com/{bucket}/", timeout=5, follow_redirects=False)
        return bucket, r["status"]

    s3_results   = await asyncio.gather(*[check_s3(v) for v in variants[:15]])
    azure_vars   = [name, name.replace("-", ""), f"{name}storage", f"{name}data"]
    azure_results = await asyncio.gather(*[check_azure(v) for v in azure_vars])
    gcp_results  = await asyncio.gather(*[check_gcp(v) for v in variants[:8]])

    for bucket, code in s3_results:
        if code == 200:
            findings.append(f("critical", f"S3 Bucket Public: {bucket}",
                               f"https://{bucket}.s3.amazonaws.com/ returns 200",
                               "Set bucket policy to private immediately"))
            records.append({"Provider": "AWS S3", "Resource": f"{bucket}.s3.amazonaws.com",
                            "Status": "PUBLIC READ", "Exposed": "YES"})
        elif code == 403:
            records.append({"Provider": "AWS S3", "Resource": f"{bucket}.s3.amazonaws.com",
                            "Status": "Exists (403)", "Exposed": "No"})

    for account, code in azure_results:
        if code == 200:
            findings.append(f("critical", f"Azure Blob Exposed: {account}",
                               f"https://{account}.blob.core.windows.net/$web/ is public",
                               "Set container access to private"))
            records.append({"Provider": "Azure Blob", "Resource": f"{account}.blob.core.windows.net",
                            "Status": "PUBLIC", "Exposed": "YES"})
        elif code == 403:
            records.append({"Provider": "Azure Blob", "Resource": f"{account}.blob.core.windows.net",
                            "Status": "Exists (403)", "Exposed": "No"})

    for bucket, code in gcp_results:
        if code == 200:
            findings.append(f("critical", f"GCP Storage Exposed: {bucket}",
                               f"storage.googleapis.com/{bucket} is readable",
                               "Update bucket IAM — remove allUsers"))
            records.append({"Provider": "GCP Storage", "Resource": f"storage.googleapis.com/{bucket}",
                            "Status": "PUBLIC", "Exposed": "YES"})

    exposed = sum(1 for r in records if r.get("Exposed") == "YES")
    if not exposed:
        findings.append(f("pass", "No Exposed Cloud Storage", "No public buckets with tested names",
                           "Check with more name variants manually"))

    return ok({"summary": {"Company": name, "Resources Checked": len(records),
                            "Exposed": exposed},
               "findings": findings, "records": records,
               "record_columns": ["Provider", "Resource", "Status", "Exposed"]})
