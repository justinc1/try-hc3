#!/usr/bin/env python3

import hashlib
import hmac


def verify_signature(payload_body: bytes, secret_token: str, signature_header: str):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Raise and return 403 if not authorized.

    Args:
        payload_body: original request body to verify (request.body())
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    if not signature_header:
        raise Exception("Webhook x-hub-signature-256 header is missing!")
    expected_signature = compute_signature(payload_body, secret_token)
    if not hmac.compare_digest(expected_signature, signature_header):
        raise Exception("Webhook request signatures didn't match!")


def compute_signature(payload_body: bytes, secret_token: str):
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    signature = "sha256=" + hash_object.hexdigest()
    return signature


def compute_signature_sha1(payload_body: bytes, secret_token: str):
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha1)
    signature = "sha1=" + hash_object.hexdigest()
    return signature


def unit_test():
    secret_token = "It's a Secret to Everybody"
    payload_body = "Hello, World!".encode("utf-8")
    payload_body = b"Hello, World!"
    signature_header = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    verify_signature(payload_body, secret_token, signature_header)


import requests
import json
import os
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def main():
    unit_test()

    url = "https://aap.jcpc.vm:8443/api/v2/job_templates/9/github/"
    token = os.environ["GH_TOKEN"]
    body = open("push.json", "rb").read().strip()
    # X-GitHub-Delivery needs to be unique.
    # X-Hub-Signature needs to match.
    # X-Hub-Signature-256 is ignored.
    headers = {
        "X-GitHub-Delivery": "72d3162e-cc78-11e3-81ab-4c9367dc095d",
        "X-Hub-Signature": compute_signature_sha1(body, token),
        "X-Hub-Signature-256": compute_signature(body, token + "blabla-invalid"),
        "User-Agent": "GitHub-Hookshot/044aadd",
        "X-GitHub-Event": "push",
        "X-GitHub-Hook-ID": "292430183",
        "X-GitHub-Hook-Installation-Target-ID": "79929171",
        "X-GitHub-Hook-Installation-Target-Type": "repository",
        "Content-Type": "application/json",
    }
    # print(f"headers={headers}")
    response = requests.post(url, data=body, verify=False, headers=headers)
    print(f"status={response.status_code} response={response}")


if __name__ == "__main__":
    main()
