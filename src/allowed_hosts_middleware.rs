// this file implements a middleware that checks if the incoming request comes from an allowed host.
// it compares the client's ip with a list of allowed hosts and returns a forbidden response if not allowed.

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpResponse};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;

pub struct AllowedHostsMiddleware {
    pub allowed_hosts: Vec<String>,
}

impl<S> Transform<S, ServiceRequest> for AllowedHostsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<BoxBody>>, Error = Error>
        + 'static,
{
    type Response = ServiceResponse<EitherBody<BoxBody>>;
    type Error = Error;
    type Transform = AllowedHostsMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    // creates a new middleware service instance wrapping the inner service
    fn new_transform(&self, service: S) -> Self::Future {
        ok(AllowedHostsMiddlewareService {
            service: Arc::new(service),
            allowed_hosts: self.allowed_hosts.clone(),
        })
    }
}

pub struct AllowedHostsMiddlewareService<S> {
    service: Arc<S>,
    allowed_hosts: Vec<String>,
}

impl<S> Service<ServiceRequest> for AllowedHostsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<BoxBody>>, Error = Error>
        + 'static,
{
    type Response = ServiceResponse<EitherBody<BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    // checks if the inner service is ready to process the request
    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    // intercepts each request to check if the client's ip is allowed
    fn call(&self, req: ServiceRequest) -> Self::Future {
        if self.allowed_hosts.is_empty() {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }

        let peer_addr = req.peer_addr();
        if let Some(peer_addr) = peer_addr {
            let client_ip = peer_addr.ip();
            let mut allowed = false;
            for host in &self.allowed_hosts {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    if ip == client_ip {
                        allowed = true;
                        break;
                    }
                } else {
                    let addr_str = format!("{}:80", host);
                    if let Ok(addrs) = addr_str.to_socket_addrs() {
                        for addr in addrs {
                            if addr.ip() == client_ip {
                                allowed = true;
                                break;
                            }
                        }
                    }
                }
            }
            if !allowed {
                let response = HttpResponse::Forbidden().body("access denied: host not allowed");
                return Box::pin(
                    async move { Ok(req.into_response(response.map_into_right_body())) },
                );
            }
        } else {
            let response =
                HttpResponse::Forbidden().body("access denied: could not determine remote address");
            return Box::pin(async move { Ok(req.into_response(response.map_into_right_body())) });
        }
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
