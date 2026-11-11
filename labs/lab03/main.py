"""FastAPI-застосунок ЛР №3: реєстр вразливостей вебзастосунку (варіант 1)."""

import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from labs.lab03.config import APP_DESCRIPTION, APP_TITLE
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from labs.lab03.schemas import StudentRead
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger("labs.lab03")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску (без заповнення даними)."""
    initialize_database()
    yield


app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(sqlite3.Error)
def handle_database_error(_: Request, exc: sqlite3.Error) -> JSONResponse:
    """Записати технічну помилку в журнал і повернути клієнту загальне повідомлення."""
    logger.error("Помилка SQLite: %s", exc, exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Внутрішня помилка роботи з базою даних"},
    )


@app.get("/ping", tags=["service"], summary="Перевірка доступності API")
def ping() -> dict[str, str]:
    """Повернути статус ok."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentRead,
    tags=["service"],
    summary="Дані студента",
)
def student() -> dict:
    """Повернути ПІБ, групу та номер варіанта зі shared/student.py."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
