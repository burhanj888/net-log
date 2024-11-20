use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
// use actix_service::ServiceFactory;
use futures::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::task::{Context, Poll};
// use std::pin::Pin;

pub struct JwtMiddleware {
    pub secret: String,
}

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareService {
            service,
            secret: self.secret.clone(),
        })
    }
}

pub struct JwtMiddlewareService<S> {
    service: S,
    secret: String,
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Clone the secret and capture the headers before moving `req`
        let secret = self.secret.clone();
        let headers = req.headers().clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            if let Some(auth_header) = headers.get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = &auth_str[7..];
                        let validation = Validation::new(Algorithm::HS256);
                        match decode::<serde_json::Value>(
                            token,
                            &DecodingKey::from_secret(secret.as_ref()),
                            &validation,
                        ) {
                            Ok(decoded_token) => {
                                // if let Some(sub) =
                                //     decoded_token.claims.get("sub").and_then(|v| v.as_str())
                                // {
                                //     req.extensions_mut().insert(sub.to_string());
                                // }
                                // Continue with the original future (call to the next service)
                                return fut.await;
                            }
                            Err(_) => {
                                return Err(actix_web::error::ErrorUnauthorized("Invalid token"))
                            }
                        }
                    }
                }
            }
            Err(actix_web::error::ErrorUnauthorized(
                "Authorization header missing or malformed",
            ))
        })
    }
}
