import asyncio
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from routers import routers
from src.db_connect import mongodb
from src.log_parser import update_log_db
from src.update_iptables_rules_to_db import rewrite


@asynccontextmanager
async def lifespan(app: FastAPI):
    mongodb.connect()
    await rewrite()
    asyncio.create_task(update_log_db())
    yield
    mongodb.close()


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
for router in routers:
    app.include_router(router)


@app.get(path="/")
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8080,
        log_level="debug",
        reload=True,
    )
