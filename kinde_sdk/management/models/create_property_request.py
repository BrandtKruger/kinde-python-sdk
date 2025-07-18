# coding: utf-8

"""
    Kinde Management API

     Provides endpoints to manage your Kinde Businesses.  ## Intro  ## How to use  1. [Set up and authorize a machine-to-machine (M2M) application](https://docs.kinde.com/developer-tools/kinde-api/connect-to-kinde-api/).  2. [Generate a test access token](https://docs.kinde.com/developer-tools/kinde-api/access-token-for-api/)  3. Test request any endpoint using the test token 

    The version of the OpenAPI document: 1
    Contact: support@kinde.com
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


from __future__ import annotations
import pprint
import re  # noqa: F401
import json

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, field_validator
from typing import Any, ClassVar, Dict, List, Optional
from typing import Optional, Set
from typing_extensions import Self

class CreatePropertyRequest(BaseModel):
    """
    CreatePropertyRequest
    """ # noqa: E501
    name: StrictStr = Field(description="The name of the property.")
    description: Optional[StrictStr] = Field(default=None, description="Description of the property purpose.")
    key: StrictStr = Field(description="The property identifier to use in code.")
    type: StrictStr = Field(description="The property type.")
    context: StrictStr = Field(description="The context that the property applies to.")
    is_private: StrictBool = Field(description="Whether the property can be included in id and access tokens.")
    category_id: StrictStr = Field(description="Which category the property belongs to.")
    __properties: ClassVar[List[str]] = ["name", "description", "key", "type", "context", "is_private", "category_id"]

    @field_validator('type')
    def type_validate_enum(cls, value):
        """Validates the enum"""
        if value not in set(['single_line_text', 'multi_line_text']):
            raise ValueError("must be one of enum values ('single_line_text', 'multi_line_text')")
        return value

    @field_validator('context')
    def context_validate_enum(cls, value):
        """Validates the enum"""
        if value not in set(['org', 'usr', 'app']):
            raise ValueError("must be one of enum values ('org', 'usr', 'app')")
        return value

    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        protected_namespaces=(),
    )


    def to_str(self) -> str:
        """Returns the string representation of the model using alias"""
        return pprint.pformat(self.model_dump(by_alias=True))

    def to_json(self) -> str:
        """Returns the JSON representation of the model using alias"""
        # TODO: pydantic v2: use .model_dump_json(by_alias=True, exclude_unset=True) instead
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> Optional[Self]:
        """Create an instance of CreatePropertyRequest from a JSON string"""
        return cls.from_dict(json.loads(json_str))

    def to_dict(self) -> Dict[str, Any]:
        """Return the dictionary representation of the model using alias.

        This has the following differences from calling pydantic's
        `self.model_dump(by_alias=True)`:

        * `None` is only added to the output dict for nullable fields that
          were set at model initialization. Other fields with value `None`
          are ignored.
        """
        excluded_fields: Set[str] = set([
        ])

        _dict = self.model_dump(
            by_alias=True,
            exclude=excluded_fields,
            exclude_none=True,
        )
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of CreatePropertyRequest from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "name": obj.get("name"),
            "description": obj.get("description"),
            "key": obj.get("key"),
            "type": obj.get("type"),
            "context": obj.get("context"),
            "is_private": obj.get("is_private"),
            "category_id": obj.get("category_id")
        })
        return _obj


