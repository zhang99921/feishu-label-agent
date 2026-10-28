# HTTP 参数模型：只接收业务字段，身份/角色/action 不允许从请求体注入。
# unit=唯一货物/托盘业务ID；batch=批次记录ID；location=目标仓库区域的业务码。
# expected_version=客户端读取时的库存版本；boxes=本次操作的整箱数量。
"""Explicit HTTP commands; identity, roles and actions are server controlled."""
from typing import Annotated

from pydantic import BaseModel,ConfigDict,Field,StrictBool,StringConstraints,field_validator

Text = Annotated[str,StringConstraints(strict=True,min_length=1,max_length=200,pattern=r"\S")]
Version = Annotated[int,Field(strict=True,ge=0)]
Boxes = Annotated[int,Field(strict=True,gt=0)]


# 禁止额外字段和隐式类型转换；例如字符串数字、布尔值不能伪装成箱数或版本。
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


# 所有流转共有参数；expected_version 过期时需刷新库存后重新确认。
class Movement(StrictModel):
    unit: Text
    batch: Text
    expected_version: Version


# 入库、转仓、重新入库都必须指定目标仓。
class DestinationMovement(Movement):
    location: Text


# boxes 是本次出库箱数，不是出库后的剩余箱数。
class PartialMovement(Movement):
    boxes: Boxes


# boxes 是重新入库时确认的箱数；confirmed 必须为布尔真值。
class ReentryMovement(DestinationMovement):
    boxes: Boxes
    confirmed: StrictBool

    @field_validator("confirmed")
    @classmethod
    def explicit_confirmation(cls,value):
        if value is not True:
            raise ValueError("explicit confirmation required")
        return value


# reference 指向原操作ID；reason 和 confirmed 用于记录人工核实依据。
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


# boxes 是更正后的箱数；数量规则还会校验它是否与当前在库状态一致。
class CorrectionMovement(UndoMovement):
    boxes: Boxes
