from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from src.auth import exceptions, schemas, crypto, utils, validation

if TYPE_CHECKING:
    from src.auth.transport import Transport


class AuthClient:
    def __init__(
        self, 
        transport: Transport,
        public_key: Optional[str] = None,
        private_key: Optional[str] = None,
        pk: Optional[str] = None,
        pk_tag: Optional[str] = None,
        device_id: Optional[str] = None,
        install_id: Optional[str] = None,
        pin_hash: Optional[str] = None,
        x509: Optional[str] = None,
        token_sn: Optional[str] = None,
        user_id_hash: Optional[str] = None,
        raw_mode: bool = False,
    ):
        self.transport = transport
        self._raw_mode: bool = raw_mode
        self.step: schemas.Step = schemas.Step.FIRST
        self.process_id: Optional[str] = None
        self.authenticated: bool = False

        self.public_key: str = public_key
        self.private_key: str = private_key
        self.pk: str = pk
        self.pk_tag: str = pk_tag
        self.device_id: str = device_id
        self.install_id: str = install_id
        self.pin_hash: str = pin_hash

        self.token_sn: str = token_sn
        self.x509: str = x509
        self.user_id_hash: str = user_id_hash
    
    def __str__(self) -> str:
        def mask(value: Optional[str]) -> str:
            if value is None:
                return "None"
            return value[:2] + "*****" + value[-2:]

        return (
            f"AuthClient("
                f"public_key={mask(self.public_key)}, "
                f"private_key={mask(self.private_key)}, "
                f"pk={mask(self.pk)}, "
                f"pk_tag={mask(self.pk_tag)}, "
                f"device_id={mask(self.device_id)}, "
                f"install_id={mask(self.install_id)}, "
                f"pin_hash={mask(self.pin_hash)}, "
                f"raw_mode={self._raw_mode}, "
                f"step={self.step}, "
                f"process_id={mask(self.process_id)}, "
                f"token_sn={mask(self.token_sn)}, "
                f"x509={mask(self.x509)}"
            )

    @classmethod
    async def from_files(cls, transport: Transport, raw_mode: bool = False, with_session: bool = True) -> AuthClient:
        if not utils.check_keys_device():
            private_key, public_key = crypto.generate_keypair_base64()
            pin_hash = crypto.generate_pin_hash()
            device_id = crypto.generate_upper_uuid()
            install_id = crypto.generate_upper_uuid()
            utils.save_device(device_id, install_id, pin_hash)
            utils.save_keys(private_key, public_key)

        self = cls(transport, raw_mode=raw_mode)

        if with_session:
            if not utils.check_session():
                raise exceptions.KaspiPayError("Session not found")
            self.x509, self.token_sn, self.user_id_hash = utils.get_session()

        self.private_key, self.public_key = crypto.get_keys()
        self.device_id, self.install_id, self.pin_hash = utils.get_device()
        self.pk = crypto.get_pk(self.public_key)
        self.pk_tag = crypto.get_pk_tag(self.public_key)

        if with_session:
            if await self._is_valid_session(
                self.x509, 
                self.token_sn, 
                self.user_id_hash, 
                self.device_id, 
                self.install_id, 
                self.pin_hash, 
                self.public_key,
                self.private_key,
                self.pk,
                self.pk_tag,
            ):
                self.authenticated = True
                return self
            raise exceptions.KaspiPayError("Session is not valid")
        return self

    @staticmethod
    async def _is_valid_session(
        x509: str, 
        token_sn: str, 
        user_id_hash: str, 
        device_id: str, 
        install_id: str, 
        pin_hash: str, 
        public_key: str,
        private_key: str,
        pk: str,
        pk_tag: str,
    ) -> bool:
        "Заглушка, нужно доработать" 
        return True

    def _check_step(self, step: schemas.Step) -> None:
        if self.step != step:
            raise exceptions.KaspiPayError(f"Incorrect step: {self.step}, expected {step}")
    
    def _already_auth(self) -> None:
        if self.authenticated:
            raise exceptions.KaspiPayError("You are already authenticated, but you call auth method")
    
    async def me(self):
        pass
        
    async def init(self) -> schemas.Meta:
        self._already_auth()
        self._check_step(schemas.Step.FIRST)
            
        body_data: schemas.FirstStepRequestData = schemas.FirstStepRequestData(
            deviceId=self.device_id,
            installId=self.install_id,
        )   

        body: schemas.FirstStepRequest = schemas.FirstStepRequest(
            Data=body_data    
        )

        headers: schemas.StepHeaders = schemas.StepHeaders(
            Cookie=schemas.StepCookie(
                deviceId=self.device_id,
                installId=self.install_id,
                pk=self.pk,
                pkTag=self.pk_tag,
            ),
            Referer=body_data.referer,
        )

        data: dict = await self.transport.post(
            "api/v1/entrance/step",
            payload=body,   
            headers=headers,
        )
        meta = validation.ResponseValidator.init(data)
        self.process_id = meta.p_id
        self.step = schemas.Step.SECOND
        return meta if not self._raw_mode else data
        

    async def send_otp(self, phone_number: str) -> schemas.Meta:
        self._already_auth()
        self._check_step(schemas.Step.SECOND)
            
        body = schemas.SecondStepRequest(
            data=schemas.SecondStepRequestData(phoneNumber=phone_number),
            meta=schemas.Meta(
                pId=self.process_id,
                sn=schemas.SN.VIEW_ENTER_OTP,
            ),
        )

        headers: schemas.StepHeaders = schemas.StepHeaders(
            Cookie=schemas.StepCookie(
                deviceId=self.device_id,
                installId=self.install_id,
                pk=self.pk,
                pkTag=self.pk_tag,
            ),
            Referer=body.referer,
        )

        data: dict = await self.transport.post(
            "api/v1/entrance/step",
            payload=body,
            headers=headers,
        )
        self.step = schemas.Step.THIRD
        return validation.ResponseValidator.send_otp(data) if not self._raw_mode else data

    async def confirm_otp(self, otp: str) -> schemas.Meta:
        self._already_auth()
        self._check_step(schemas.Step.THIRD)
        
        body = schemas.ThirdStepRequest(
            data=schemas.ThirdStepRequestData(userOtp=otp),
            meta=schemas.Meta(
                pId=self.process_id,
                sn=schemas.SN.VIEW_ENTER_LOGIN_PASSWORD,
            ),
        )

        headers: schemas.StepHeaders = schemas.StepHeaders(
            Cookie=schemas.StepCookie(
                deviceId=self.device_id,
                installId=self.install_id,
                pk=self.pk,
                pkTag=self.pk_tag,
            ),
            Referer=body.referer,
        )

        data: dict = await self.transport.post(
            "api/v1/entrance/step",
            payload=body,
            headers=headers,
        )
        self.step = schemas.Step.FINISH
        return validation.ResponseValidator.confirm_otp(data) if not self._raw_mode else data

    async def finish(self) -> schemas.FinishResponse:
        self._already_auth()
        self._check_step(schemas.Step.FINISH)

        data_to_sign: schemas.DataToSign = schemas.DataToSign(
            installId=self.install_id,
            auth=[
                schemas.Auth()
            ],
            time=utils.get_current_time()
        )
        
        body: schemas.FinishRequest = schemas.FinishRequest(
            guard=schemas.Guard(pinHash=self.pin_hash, x509=self.public_key),
            processId=self.process_id,
            signed=schemas.Signed(
                data=data_to_sign.base64(),
                sign=crypto.sign_data(data_to_sign.base64(), private_key=self.private_key)
            ),
        )
        finish_url: str = f"{self.transport.base_url}/api/v1/kpentrance/finish"

        pre_headers: schemas.PreFinishHeaders = schemas.PreFinishHeaders(
            x_time=utils.get_current_time(),
            x_pktag=self.pk_tag,
            x_su=crypto.compute_x_su(url=finish_url)
        )
        x_sign: str = crypto.compute_x_sign(url=finish_url, headers=pre_headers.model_dump(by_alias=True), x_sh=pre_headers.x_sh)

        headers: schemas.FinishHeaders = schemas.FinishHeaders(
            **pre_headers.model_dump(by_alias=True),
            **{"x-sign": x_sign},
        )

        data: dict = await self.transport.post(
            "api/v1/kpentrance/finish",
            payload=body,
            headers=headers,
        )
        result: schemas.FinishResponse = validation.ResponseValidator.finish(data) 
        self.token_sn = result.token_sn
        self.x509 = result.x509
        self.user_id_hash = result.user_id_hash
        utils.save_session(self.x509, self.token_sn, self.user_id_hash)
        return result if not self._raw_mode else data

    async def logout(self) -> None:
        #TODO: Закончить
        body: schemas.LogoutRequest = schemas.LogoutRequest(
            DeviceId=self.device_id,
            TokenSn=self.token_sn,
        )
