from __future__ import annotations

import argparse
from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse

from dashboard import views

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(db_path: str | Path) -> FastAPI:
    app = FastAPI(title="TXDX ETL Dashboard")

    @app.get("/api/overview")
    def api_overview(
        cycles: int = Query(30, ge=1, le=500),
        events: int = Query(80, ge=1, le=500),
    ) -> dict:
        return views.overview(
            db_path, cycles_limit=cycles, events_limit=events
        )

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="TXDX ETL local dashboard")
    parser.add_argument(
        "--db",
        default="runtime/spool.db",
        help="Ruta al archivo SQLite compartido por el ETL",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    import uvicorn

    app = create_app(args.db)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
