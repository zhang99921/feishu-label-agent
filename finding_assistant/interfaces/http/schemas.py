"""Explicit HTTP commands; identity, roles and actions are server controlled."""
from typing import Annotated

from pydantic import BaseModel,ConfigDict,Field,StrictBool,StringConstraints,field_validator

Text = Annotated[str,StringConstraints(strict=True,min_length=1,max_length=200,pattern=r"\S")]
Version = Annotated[int,Field(strict=True,ge=0)]
Boxes = Annotated[int,Field(strict=True,gt=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid",strict=True)

    @field_validator("*",mode="after",check_fields=False)
    @classmethod
    def no_blank_strings(cls,value):
        if isinstance(value,str) and not value.strip():
            raise ValueError("nonblank value required")
        return value


class InventoryQuery(StrictModel):
    batch: Text


class Movement(StrictModel):
    unit: Text
    batch: Text
    expected_version: Version


class DestinationMovement(Movement):
    location: Text


class PartialMovement(Movement):
    boxes: Boxes


class ReentryMovement(DestinationMovement):
    boxes: Boxes
    confirmed: StrictBool

    @field_validator("confirmed")
    @classmethod
    def explicit_confirmation(cls,value):
        if value is not True:
            raise ValueError("explicit confirmation required")
        return value


class UndoMovement(Movement):
    reference: Text
    reason: Annotated[str,StringConstraints(strict=True,min_length=1,max_length=2000)]
    confirmed: StrictBool

    @field_validator("confirmed")
    @classmethod
    def explicit_confirmation(cls,value):
        if value is not True:
            raise ValueError("explicit confirmation required")
        return value


class CorrectionMovement(UndoMovement):
    boxes: Boxes
