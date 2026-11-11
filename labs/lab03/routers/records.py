"""Маршрути для записів (знахідок вебаудиту)."""

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from labs.lab03 import repository
from labs.lab03.config import BULK_MAX_ITEMS, VALUE_MAX, VALUE_MIN
from labs.lab03.repository import ConflictError, NotFoundError
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace, Status

router = APIRouter(prefix="/records", tags=["records"])

RecordId = Annotated[int, Path(gt=0, description="Додатний id запису")]

NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"description": "Запис з таким code уже існує"}}


def _to_http(exc: Exception) -> HTTPException:
    """Перетворити виняток шару даних на HTTP-помилку."""
    if isinstance(exc, NotFoundError):
        return HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))


@router.get("", response_model=list[RecordRead], summary="Список записів з фільтрами")
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цієї категорії")
    ] = None,
    record_status: Annotated[
        Status | None, Query(alias="status", description="Лише записи з цим статусом")
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=VALUE_MIN,
            le=VALUE_MAX,
            allow_inf_nan=False,
            description="value >= min_value (score 0–10)",
        ),
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Буквальний підрядок у title з урахуванням регістру",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Максимум записів")] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,
) -> list[dict]:
    """Повернути записи, відсортовані за id; фільтри об’єднуються через AND."""
    return repository.list_records(
        category_id=category_id,
        status=record_status,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис",
    responses=NOT_FOUND,
)
def get_record(record_id: RecordId) -> dict:
    """Повернути один запис за id."""
    record = repository.get_record(record_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Запис не знайдено")
    return record


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(payload: RecordCreate) -> dict:
    """Створити запис; id генерує база."""
    try:
        return repository.create_record(payload.model_dump())
    except (NotFoundError, ConflictError) as exc:
        raise _to_http(exc) from exc


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення записів (атомарно)",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    payload: Annotated[
        list[RecordCreate],
        Body(min_length=1, max_length=BULK_MAX_ITEMS, description="JSON-масив записів"),
    ],
) -> list[dict]:
    """Створити 1–100 записів в одній транзакції: усі або жодного."""
    try:
        return repository.create_records_bulk(item.model_dump() for item in payload)
    except (NotFoundError, ConflictError) as exc:
        raise _to_http(exc) from exc


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повна заміна змінюваних полів запису",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, payload: RecordReplace) -> dict:
    """Замінити всі п’ять змінюваних полів; id залишається незмінним."""
    try:
        return repository.replace_record(record_id, payload.model_dump())
    except (NotFoundError, ConflictError) as exc:
        raise _to_http(exc) from exc


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити запис",
    responses=NOT_FOUND,
)
def delete_record(record_id: RecordId) -> None:
    """Видалити запис за id."""
    try:
        repository.delete_record(record_id)
    except NotFoundError as exc:
        raise _to_http(exc) from exc
