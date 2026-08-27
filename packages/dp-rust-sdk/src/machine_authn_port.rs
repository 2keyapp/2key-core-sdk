//! Port for billing Machine AuthN HTTP (implemented by `billing_http` and `DpClient`).

use async_trait::async_trait;
use billing_http::MachineAuthnClient;

use crate::client::DpClient;
use crate::error::Result;
use crate::types::{
    EnrollApproveRequest, EnrollApproveResponse, EnrollCreateRequest, EnrollCreateResponse,
    EnrollPullResponse, KickstartRequest, KickstartResponse, PlatformRootResponse,
};

/// Async port for machine enrollment HTTP against billing `/api/v1/machine-authn/*`.
#[async_trait]
pub trait MachineAuthnPort: Send + Sync {
    async fn kickstart_entity(&self, req: &KickstartRequest) -> Result<KickstartResponse>;
    async fn enroll_create(&self, req: &EnrollCreateRequest) -> Result<EnrollCreateResponse>;
    async fn enroll_pull(&self, pull_token: &str) -> Result<EnrollPullResponse>;
    async fn enroll_approve(
        &self,
        req: &EnrollApproveRequest,
    ) -> Result<EnrollApproveResponse>;
    async fn platform_root(&self) -> Result<PlatformRootResponse>;
}

#[async_trait]
impl MachineAuthnPort for DpClient {
    async fn kickstart_entity(&self, req: &KickstartRequest) -> Result<KickstartResponse> {
        DpClient::kickstart_entity(self, req).await
    }

    async fn enroll_create(&self, req: &EnrollCreateRequest) -> Result<EnrollCreateResponse> {
        DpClient::enroll_create(self, req).await
    }

    async fn enroll_pull(&self, pull_token: &str) -> Result<EnrollPullResponse> {
        DpClient::enroll_pull(self, pull_token).await
    }

    async fn enroll_approve(
        &self,
        req: &EnrollApproveRequest,
    ) -> Result<EnrollApproveResponse> {
        DpClient::enroll_approve(self, req).await
    }

    async fn platform_root(&self) -> Result<PlatformRootResponse> {
        DpClient::platform_root(self).await
    }
}

#[async_trait]
impl MachineAuthnPort for MachineAuthnClient {
    async fn kickstart_entity(&self, req: &KickstartRequest) -> Result<KickstartResponse> {
        self.register(req).await.map_err(Into::into)
    }

    async fn enroll_create(&self, req: &EnrollCreateRequest) -> Result<EnrollCreateResponse> {
        self.enroll_create(req).await.map_err(Into::into)
    }

    async fn enroll_pull(&self, pull_token: &str) -> Result<EnrollPullResponse> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            pull_token: &'a str,
        }
        self.enroll_pull(&Body { pull_token })
            .await
            .map_err(Into::into)
    }

    async fn enroll_approve(
        &self,
        req: &EnrollApproveRequest,
    ) -> Result<EnrollApproveResponse> {
        self.enroll_approve(req).await.map_err(Into::into)
    }

    async fn platform_root(&self) -> Result<PlatformRootResponse> {
        self.platform_root().await.map_err(Into::into)
    }
}
