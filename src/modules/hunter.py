import re
import time
from tqdm import tqdm

from typing import Any
from .map_share import share_paths
from .verbosity_logging import logger
from .read_file import read_file
from impacket.smbconnection import SMBConnection

secrets : list[dict[str, Any]] = []
desc: str = "Scanning"
bar_format: str = "{l_bar}{bar} | {n_fmt}/{total_fmt} items | {remaining}"


def hunter(file_content: bytes, path: str, regex: str|None=None) -> list[dict[str, Any]]:
    """Receives the file content and looks for promising patterns that may indicate secrets"""
    patterns: dict[str, str] = {
        "Custom regex": rf"{regex}"
    } if regex else {
        "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35,70}", "Google reCAPTCHA Key": r"6L[0-9A-Za-z-_]{38,47}", "Google OAuth Token": r"ya29\.[0-9A-Za-z\-_]+", "AWS Access Key": r"AKIA[0-9A-Z]{16}", "AWS Secret Access Key": r"aws.*?['\"][0-9a-zA-Z/+]{40}['\"]", "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20,22}", "GitHub Token": r"ghp_[0-9a-zA-Z]{36}", "GitHub Token v2": r"github_pat_[0-9a-zA-Z_]{20,}", "Slack Token": r"xox[baprs]-[0-9A-Za-z-]+", "Shopify Access Token": r"shpat_[0-9a-fA-F]{32}", "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "Facebook Access Token": r"EAAB[a-zA-Z0-9]+", "Mailgun API Key": r"key-[0-9a-zA-Z]{32}", "Twilio API Key": r"SK[0-9a-fA-F]{32}", "Twilio Account SID": r"AC[a-zA-Z0-9]{32}", "Stripe API Key": r"\bsk_live_[0-9a-zA-Z]{24}", "Basic Auth Header": r"basic\s*[a-zA-Z0-9=:_\+\/-]+", "Bearer Token": r"bearer\s+[a-zA-Z0-9._-]+", "Private Key": r"-----BEGIN (?:RSA |DSA |EC |PGP )?PRIVATE KEY(?: BLOCK)?-----", "JSON Web Token": r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b", "Bearer JWT": r"Bearer [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "Email address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}", "URL": r"https?://(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[\w\-._~:/?#\[\]@!$&'()*+,;=]*)?", "IP Address": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", "UUID": r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}", "Password": r"(?:password|passwd|pwd|pass)\s*[=:]\s*['\"]?([a-zA-Z0-9@_\-!]{8,})['\"]?", "Command Line Password": r"-p\s+['\"]([^'\"]+)['\"]", "API Key Assigned": r"(?:api[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", "MongoDB URI": r"mongodb(\+srv)?:\/\/[^\s'\"]+", "PostgreSQL URI": r"postgres(?:ql)?:\/\/[^\s'\"]+", "MySQL URI": r"mysql:\/\/[^\s'\"]+", "Redis URI": r"redis:\/\/[^\s'\"]+", "Elastic Search URI": r"elasticsearch:\/\/[^\s'\"]+", "Supabase DB Key": r"supabase\.co\/[a-z0-9]{15,}", "Firebase URL": r"https:\/\/[a-z0-9-]+\.firebaseio\.com", "JDBC URL": r"jdbc:\w+:\/\/[^\s'\"]+", "AWS RDS Hostname": r"[a-z0-9-]+\.rds\.amazonaws\.com", "Cloud SQL URI (GCP)": r"googleapis\.com\/sql\/v1beta4\/projects\/", "GitHub OAuth App Secret": r"[a-f0-9]{40}", "Azure Storage Key": r"AccountKey=[a-zA-Z0-9+/=]{60,100}", "Discord Bot Token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}", "SendGrid API Key": r"SG\.[\w\d\-_]{22}\.[\w\d\-_]{43}", "Stripe Webhook Secret": r"whsec_[a-zA-Z0-9_\-]{32,48}", "GitHub Fine-grained Token": r"github_pat_[0-9a-zA-Z_]{82}", "Slack Webhook": r"https://hooks.slack.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[a-zA-Z0-9]{24}", "Firebase Secret": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", "Username in config": r"(?:username|user|login|uid)\s*[=:]\s*['\"]?([a-zA-Z0-9._-]{3,50})['\"]?", "Email as username": r"(?:username|user)\s*[=:]\s*['\"]?([a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})['\"]?", "URL username": r"://([^:]+):[^@]+@", "Basic Auth username": r"(?:username|user)\s*:\s*['\"]?([^'\"]+)['\"]?"
    }
    
    lines : list[str] = file_content.decode("utf-8", errors="replace").splitlines()
    file_secrets : list[dict[str, str]] = []

    for i, line in enumerate(lines, start=1):
        for secret_type, secret_regex in patterns.items():
            for match in re.finditer(secret_regex, line, flags=re.IGNORECASE):
                if match.groups():
                    secret_val : str = match.group(1)
                else:
                    secret_val = match.group(0)
                secret : dict[str,Any] = {
                        "File Path" : path,
                        "Type" : secret_type,
                        "Secret" : secret_val,
                        "Context" : line.strip(),
                        "Line" : i
                    }
                file_secrets.append(secret)
    return file_secrets if file_secrets else []

def scan_all_shares(session: SMBConnection, regex: str) -> None:
    """Scans for secrets on all shares"""
    for share, file_paths in share_paths.items():
        try:
            with tqdm(total=len(file_paths), desc=desc, bar_format=bar_format) as pb:
                for full_path, _, _ in file_paths:
                    _, file_content = read_file(
                        session=session,
                        share=share,
                        full_path=full_path
                    )

                    file_secrets = hunter(
                        file_content=file_content,
                        path=full_path,
                        regex=regex
                    )

                    secrets.extend(file_secrets)
                    time.sleep(0.5)
                    pb.update(1)

        except Exception as e:
            logger.error(f"Unhandled error hunting for secrets in {full_path}: {e}")

def scan_share(session: SMBConnection, share_name: str, regex: str) -> None:
    """Scans for secrets on a given share"""
    for share_item in share_paths.items():
        share, file_paths = share_item
        try:
            if share_name.lower() == share.name.lower():
                with tqdm(total=len(file_paths), desc=desc, bar_format=bar_format) as pb:
                    for full_path, _, _ in file_paths:
                        _, file_content = read_file(
                            session=session,
                            share=share,
                            full_path=full_path
                        )
                        file_secrets = hunter(
                            file_content=file_content,
                            path=full_path,
                            regex=regex
                        )
                        secrets.extend(file_secrets)
                        time.sleep(0.5)
                        pb.update(1)
                        
        except Exception as e:
            logger.error(f"Unhandled error hunting for secrets in {full_path}: {e}")

def scan_file(session: SMBConnection, share_name: str, path: str, regex: str) -> None:
    """Scans for secrets on a specific file from a given share"""
    for share_item in share_paths.items():
        share, file_paths = share_item
        try:
            if share_name.lower() == share.name.lower() and path in file_paths[0]:
                _, file_content = read_file(
                    session=session,
                    share=share,
                    full_path=path
                )
                file_secrets = hunter(
                    file_content=file_content,
                    path=path,
                    regex=regex
                )
                secrets.extend(file_secrets)
        except Exception as e:
            logger.error(f"Unhandled error hunting for secrets in {path}: {e}")

def run(session: SMBConnection, recursive: bool, share_name: str="", path: str="", regex: str="") -> None:
    if not share_name and not path and recursive: # Recursive scan against all readable shares
        scan_all_shares(session=session, regex=regex)

    elif share_name and recursive and not path: # Recursive scan against a share
        scan_share(session=session, share_name=share_name, regex=regex)
    
    elif share_name and path and not recursive: # Hunt secrets on a specific file
        scan_file(session=session, share_name=share_name, path=path, regex=regex)
    
    for secret in secrets:
        logger.critical(
            f"File Path: {secret['File Path']}\n"
            f"Type: {secret['Type']}\n"
            f"Secret: {secret['Secret']}\n"
            f"Context: {secret['Context']}\n"
            f"Line: {secret['Line']}\n"
        )
        