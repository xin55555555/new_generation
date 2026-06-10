from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from src.api.index import router
from src.configs.index import API_HOST, API_PORT, CONTROL_CENTER_URL
from src.services.demo_logger import init, log


app = FastAPI(title="DDoS Policy Generation System", version="1.0.0")
app.include_router(router)


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"code": exc.status_code, "message": message})


@app.on_event("startup")
def startup() -> None:
    init()

