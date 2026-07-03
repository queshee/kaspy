import base64
import json
import uuid
from enum import Enum
from typing import Optional
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer

class Step(str, Enum):
    FIRST = "first"
    SECOND = "second"
    THIRD = "third"
    FINISH = "finish"


class ErrorCode(str, Enum):
    INVALID_PHONE_NUMBER = 'UserPhoneNumberDoesNotBelongToAnyOperator'
    INVALID_OTP = 'OtpCodeIsWrong'
    TEMPORARY_BLOCKED = 'TemporaryBlocked'
    BAD_REQUEST = 'BadIncomingRequest'
    ENTER_OTP_ATTEMPTS_EXCEEDED = 'EnterOtpAttemptsExceeded'
    CONTEXT_NOT_FOUND = 'ContextNotFound'
    PASSWORD_IS_EMPTY = 'PasswordIsEmpty'
    PASSWORD_ATTEMPTS_EXCEEDED = 'PasswordAttemptsExceeded'
    OLD_VERSION_TO_UPDATE = 'OldVersionToUpdate'
    KASPI_PAY_CHECK_SECURITY_FAILED = 'KaspiPayCheckSecurityFailed'

class SN(str, Enum):
    ENTER_PHONE_NUMBER = 'EnterPhoneNumber'
    VIEW_ENTER_OTP = 'ViewEnterOtp'
    MOBILE_DEVICE_REGISTRATION = 'MobileDeviceRegistration'
    VIEW_ENTER_LOGIN_PASSWORD = 'ViewEnterLoginPassword'
    VIEW_KASPI_ID_TAKE_PHOTO = 'ViewKaspiIdTakePhoto'
    WEB_ORG_REGISTRATION = 'WebOrgRegistration'
    SHOW_ALERT_ON_FIRST_VIEW = 'ShowAlertOnFirstView'
    SYSTEM_ERROR = 'SystemError'

class Meta(BaseModel):
    p_id: str = Field(alias="pId")
    sn: SN = Field(alias="sn")

class FirstStepRequestData(BaseModel):
    device_id: str = Field(alias="deviceId")
    install_id: str = Field(alias="installId")

    app_build: str = Field(default="1099", alias="appBuild", pattern=r"^\d+$")
    app_version: str = Field(default="4.110.1", alias="appVersion", pattern=r"^\d+\.\d+(\.\d+)?$")
    auth: str = Field(default="2", alias="auth", pattern=r"^\d$")
    device_brand: str = Field(default="Apple", alias="deviceBrand")
    device_model: str = Field(default="iPhone17,3", alias="deviceModel")
    front_camera_available: str = Field(default="true", alias="frontCameraAvailable", pattern=r"^(true|false)$")
    no_pass: str = Field(default="0", alias="noPass", pattern=r"^[01]$")
    pc: str = Field(default="KPEntrance", alias="pc")
    platform_type: str = Field(default="IOS", alias="platformType")
    platform_version: str = Field(default="18.5", alias="platformVersion")
    sf: str = Field(default="registration", alias="sf")

    @property
    def referer(self) -> str:
        return f"https://entrance-pay.kaspi.kz/process/entrance/?{urlencode(self.model_dump(by_alias=True))}"

class FirstStepRequest(BaseModel):
    dt: dict = Field(default={}, alias="data")
    data: FirstStepRequestData = Field(alias="Data")
    act_type: str = Field(default="Success", alias="actType")

class SecondStepRequestData(BaseModel):
    phone_number: str = Field(alias="phoneNumber")

    @field_validator("phone_number")
    def validate_phone_number(cls, v: str) -> str:
        if v.startswith("8") and len(v) == 11:
            v = v[1:]
        elif v.startswith("77") and len(v) == 11:
            v = v[1:]
        elif v.startswith("+77") and len(v) == 12:
            v = v[2:]

        if not v.isdigit():
            raise ValueError("Phone number must contain only digits")
        if len(v) != 10:
            raise ValueError("Phone number must be 10 digits long")
        if not v.startswith("7"):
            raise ValueError("Phone number must start with 7")
        return v


class SecondStepRequest(BaseModel):
    data: SecondStepRequestData = Field(default={}, alias="data")
    meta: Meta = Field(alias="meta")
    act_type: str = Field(default="Success", alias="actType")

    @property
    def referer(self) -> str:
        return f"https://entrance-pay.kaspi.kz/process/universal-enter-phone-number?pId={self.meta.p_id}&firstPage=KPUniversalEnterPhoneNumber"

class ThirdStepRequestData(BaseModel):
    input_type: str = Field(default="auto", alias="inputType", pattern=r"^(manual|auto)$")
    user_otp: str = Field(alias="userOtp")

    @field_validator("user_otp")
    def validate_user_otp(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("User OTP must contain only digits")
        if len(v) != 4:
            raise ValueError("User OTP must be 4 digits long")
        return v

class ThirdStepRequest(BaseModel):
    data: ThirdStepRequestData = Field(alias="data")
    meta: Meta = Field(alias="meta")
    act_type: str = Field(default="Success", alias="actType")

    @property
    def referer(self) -> str:
        return f"https://entrance-pay.kaspi.kz/process/universal-enter-phone-number?pId={self.meta.p_id}&firstPage=KPUniversalEnterPhoneNumber"

class Guard(BaseModel):
    pin_hash: str = Field(alias='pinHash')
    x509: str = Field(alias='x509')

class Auth(BaseModel):
    value: str = Field(default="", alias='value')
    type: str = Field(default="pincode", alias='type')

class DataToSign(BaseModel):
    user_id_hash: str = Field(default="", alias="userIdHash")
    auth: list[Auth] = Field(alias="auth")
    time: str = Field(alias='time')
    install_id: str = Field(alias="installId")

    def base64(self) -> str:
        return base64.b64encode(json.dumps(self.model_dump(by_alias=True)).encode("utf-8")).decode("utf-8")

class Signed(BaseModel):
    data: str = Field(alias='data')
    sign: str = Field(alias='sign')

class FinishRequest(BaseModel):
    guard: Guard = Field(alias='guard')
    process_id: str = Field(alias='processId')
    signed: Signed = Field(alias='signed')
    act_type: str = Field(default="Success", alias='actType')

class FinishResponse(BaseModel):
    token_sn: str = Field(alias='tokenSN')
    x509: str = Field(alias='x509')
    user_id_hash: str = Field(alias='userIdHash')

class LogoutRequest(BaseModel):
    device_id: str = Field(alias='DeviceId')
    token_sn: str = Field(alias="TokenSn")

class StepCookie(BaseModel):
    device_id: str = Field(alias="deviceId")
    install_id: str = Field(alias="installId")
    pk: str = Field(alias="pk")
    pk_tag: str = Field(alias="pkTag")

    is_mobile_app: str = Field(default="true", alias="is_mobile_app")
    locale: str = Field(default="ru-RU", alias="locale")
    ma_bld: str = Field(default="1099", alias="ma_bld")
    ma_platform_type: str = Field(default="IOS", alias="ma_platform_type")
    ma_platform_ver: str = Field(default="26.5", alias="ma_platform_ver")
    ma_ver: str = Field(default="4.110.1", alias="ma_ver")
    new_pay_connection: str = Field(default="true", alias="new-pay-connection")
    xs: str = Field(default="R:0|E:0|RH:0|N:0|GS:0", alias="xs")

    user_token: Optional[str] = Field(default=None, alias="user_token")

    @model_serializer
    def serialize_to_cookie_string(self) -> str:
        data = {self.model_fields[k].alias or k: v for k, v in self.__dict__.items()}
        return "; ".join(f"{k}={v}" for k, v in data.items() if v is not None)

class StepHeaders(BaseModel):
    referer: str = Field(alias="Referer")
    cookie: StepCookie = Field(alias="Cookie")

    accept: str = Field(default="application/json, text/plain, */*", alias="Accept")
    content_type: str = Field(default="application/json", alias="Content-Type")
    accept_language: str = Field(default="ru", alias="Accept-Language")
    accept_encoding: str = Field(default="gzip, deflate, br", alias="Accept-Encoding")
    origin: str = Field(default="https://entrance-pay.kaspi.kz", alias="Origin")
    sec_fetch_site: str = Field(default="same-origin", alias="Sec-Fetch-Site")
    sec_fetch_mode: str = Field(default="cors", alias="Sec-Fetch-Mode")
    sec_fetch_dest: str = Field(default="empty", alias="Sec-Fetch-Dest")
    user_agent: str = Field(
        default="Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        alias="User-Agent"
    )

class PreFinishHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    x_time: str = Field(alias="x-time")
    x_pktag: str = Field(alias="x-pktag")
    x_su: str = Field(alias="x-su")

    x_call: str = Field(default="notConnected", alias="x-call")
    user_agent: str = Field(default="Kaspi%20Pay/1104 CFNetwork/3860.600.12 Darwin/25.5.0", alias="user-agent")
    x_platform_type: str = Field(default="IOS", alias="x-platform-type")
    priority: str = Field(default="u=3, i", alias="priority")
    x_net_type: str = Field(default="WIFI/ETHERNET", alias="x-net-type")
    x_emulator: str = Field(default="0", alias="x-emulator")
    accept_language: str = Field(default="ru", alias="accept-language")
    x_locale: str = Field(default="ru-RU", alias="x-locale")
    x_sv: str = Field(default="2", alias="x-sv")
    x_request_id: str = Field(default=str(uuid.uuid4()).upper(), alias="x-request-id")
    x_time_zone: str = Field(default="GMT+05:00", alias="x-time-zone")
    content_type: str = Field(default="application/json", alias="content-type")
    accept: str = Field(default="*/*", alias="accept")
    accept_encoding: str = Field(default="gzip, deflate, br", alias="accept-encoding")
    x_sh: str = Field(default="url,X-Platform-Type,X-Time,X-Locale,X-Emulator,X-Call,X-Net-Type,X-SV,X-Time-Zone", alias="x-sh")

class FinishHeaders(PreFinishHeaders):
    x_sign: str = Field(alias="x-sign")

class LogoutHeaders(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    #TODO: Перепроверить default поля

    x_kb_client_ip: str = Field(alias="X-Kb-Client-Ip")
    x_sign: str = Field(alias="X-Sign")
    x_time: str = Field(default="2026-07-01T20:00:35.137+0500", alias="X-Time")
    x_pi: str = Field(default="3777205", alias="X-PI")
    x_kb_token_sn_mac: str = Field(alias="X-Kb-TokenSnMac")
    x_kb_token_sn: str = Field(alias="X-Kb-TokenSn")

    host: str = Field(default="mtoken.kaspi.kz", alias="Host")
    x_locale: str = Field(default="ru-RU", alias="X-Locale")
    accept: str = Field(default="*/*", alias="Accept")
    x_sv: str = Field(default="2", alias="X-SV")
    accept_language: str = Field(default="ru", alias="Accept-Language")
    accept_encoding: str = Field(default="gzip, deflate, br", alias="Accept-Encoding")
    content_type: str = Field(default="application/json", alias="Content-Type")
    x_call: str = Field(default="notConnected", alias="X-Call")
    user_agent: str = Field(default="Kaspi%20Pay/1104 CFNetwork/3860.600.12 Darwin/25.5.0", alias="User-Agent")
    connection: str = Field(default="keep-alive", alias="Connection")
    x_s: str = Field(default="R:0|E:0|RH:0|N:0|GS:0", alias="X-S")
    x_sh: str = Field(default="url,X-SV,X-Kb-Client-Ip,X-Time,X-Call,X-Locale,X-Kb-TokenSnMac,X-Kb-TokenSn,X-S,X-PI", alias="X-SH")