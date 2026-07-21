from clients.backend_client import BackendClient, PermanentDeliveryError, TransientDeliveryError


class _Response:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def json(self):
        return self._payload


class _Session:
    def __init__(self, post_response=None, put_response=None):
        self.post_response = post_response or _Response(200, payload={"upload_url": "https://s3.example/upload"})
        self.put_response = put_response or _Response(200)
        self.post_calls = []
        self.put_calls = []

    def post(self, *args, **kwargs):
        if args:
            kwargs["url"] = args[0]
        self.post_calls.append(kwargs)
        return self.post_response

    def put(self, *args, **kwargs):
        if args:
            kwargs["url"] = args[0]
        self.put_calls.append(kwargs)
        return self.put_response


def test_send_webhook_requests_upload_url_then_puts_snapshot():
    session = _Session()
    client = BackendClient(
        ingest_url="https://api.example/scans/upload-url",
        tenant_id=9,
        api_key="agent-key",
        verify_ssl=False,
    )
    client.session = session

    payload = {"scan_id": "IVM-1", "company_id": 4, "scanner_type": "insightvm", "findings": []}
    client.send_webhook(payload=payload, idempotency_key="sha256:abc", timeout=12)

    assert session.post_calls[0]["url"] == "https://api.example/scans/upload-url"
    assert session.post_calls[0]["json"] == {
        "tenant_id": 9,
        "api_key": "agent-key",
        "scanner_type": "insightvm",
        "idempotency_key": "sha256:abc",
    }
    assert session.put_calls[0]["url"] == "https://s3.example/upload"
    assert session.put_calls[0]["headers"] == {"Content-Type": "application/json"}
    assert b'"scan_id":"IVM-1"' in session.put_calls[0]["data"]


def test_send_webhook_raises_permanent_without_upload_url():
    session = _Session(post_response=_Response(200, payload={}))
    client = BackendClient(
        ingest_url="https://api.example/scans/upload-url",
        tenant_id=9,
        api_key="agent-key",
    )
    client.session = session

    try:
        client.send_webhook(payload={"scan_id": "IVM-2", "scanner_type": "insightvm"})
    except PermanentDeliveryError as exc:
        assert "upload_url" in str(exc)
    else:
        raise AssertionError("PermanentDeliveryError was not raised")


def test_send_webhook_retries_s3_transient_error(monkeypatch):
    session = _Session(put_response=_Response(503, text="slow down"))
    client = BackendClient(
        ingest_url="https://api.example/scans/upload-url",
        tenant_id=9,
        api_key="agent-key",
    )
    client.session = session
    monkeypatch.setattr("clients.backend_client.time.sleep", lambda _: None)

    try:
        client.send_webhook(payload={"scan_id": "IVM-3", "scanner_type": "insightvm"}, retries=2)
    except TransientDeliveryError as exc:
        assert "S3 upload" in str(exc)
    else:
        raise AssertionError("TransientDeliveryError was not raised")

    assert len(session.post_calls) == 2
    assert len(session.put_calls) == 2
