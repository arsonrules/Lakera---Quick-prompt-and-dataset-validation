"""Diagnose CERTIFICATE_VERIFY_FAILED: is SSL_CERT_FILE set, and who signs HTTPS on this network?
Docker: docker run --rm -i -v "$PWD/ca-bundle.pem:/certs/ca-bundle.pem:ro" -e SSL_CERT_FILE=/certs/ca-bundle.pem lakera-guard-tester python - < certcheck.py
Local:  SSL_CERT_FILE=ca-bundle.pem .venv/bin/python certcheck.py
"""
import os, socket, ssl, tempfile

f = os.environ.get("SSL_CERT_FILE")
print("SSL_CERT_FILE =", f or "(not set: only the standard CAs are trusted)")
if f:
    n = open(f, errors="ignore").read().count("-----BEGIN CERTIFICATE-----")
    print(f"bundle: {n} PEM certificates (the standard set is 100+; if the count barely moved, your proxy CA is missing)")

for host in ("huggingface.co", "api.lakera.ai"):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(socket.create_connection((host, 443), timeout=10), server_hostname=host) as s:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as t:
            t.write(ssl.DER_cert_to_PEM_cert(s.getpeercert(True)))
    issuer = ", ".join(f"{k}={v}" for rdn in ssl._ssl._test_decode_cert(t.name)["issuer"] for k, v in rdn)
    try:
        ssl.create_default_context(cafile=f).wrap_socket(socket.create_connection((host, 443), timeout=10), server_hostname=host).close()
        ok = "OK"
    except ssl.SSLError as e:
        ok = f"FAILS ({e.reason})"
    print(f"{host}: {ok}\n  certificate signed by: {issuer}")
