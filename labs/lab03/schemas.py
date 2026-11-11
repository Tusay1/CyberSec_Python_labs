"""Pydantic-моделі запитів і відповідей API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MAX, VALUE_MIN

Status = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Тіло запиту на створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40, examples=["web"])


class CategoryRead(BaseModel):
    """Категорія у відповіді API."""

    id: int = Field(gt=0)
    name: str


class RecordCreate(BaseModel):
    """Тіло запиту на створення знахідки (id задає база)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40, examples=["V01-TEST"])
    title: str = Field(min_length=3, max_length=120, examples=["Навчальна знахідка"])
    category_id: int = Field(gt=0, strict=True, examples=[1])
    value: float = Field(
        ge=VALUE_MIN,
        le=VALUE_MAX,
        allow_inf_nan=False,
        strict=True,
        description="Навчальна оцінка небезпеки, score 0–10",
        examples=[7.5],
    )
    status: Status


class RecordReplace(RecordCreate):
    """Повна заміна всіх змінюваних полів знахідки (PUT)."""


class RecordRead(RecordCreate):
    """Знахідка у відповіді API разом з id та назвою категорії."""

    id: int = Field(gt=0)
    category_name: str


class StudentRead(BaseModel):
    """Дані студента зі shared/student.py."""

    student_name: str
    group_name: str
    variant_number: int
