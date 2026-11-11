"""Маршрути для категорій."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, status

from labs.lab03 import repository
from labs.lab03.repository import ConflictError, NotFoundError
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])

CategoryId = Annotated[int, Path(gt=0, description="Додатний id категорії")]


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(payload: CategoryCreate) -> dict:
    """Створити нову категорію з унікальною назвою."""
    try:
        return repository.create_category(payload.name)
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(category_id: CategoryId) -> None:
    """Видалити категорію, якщо в ній немає записів."""
    try:
        repository.delete_category(category_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
