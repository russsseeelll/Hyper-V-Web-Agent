mod api;
mod allowed_hosts_middleware;
mod commands;
mod config;
mod logging;
mod powershell;
mod validation;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use config::{load_or_create_config, running_as_admin};
use logging::log_message;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::process;
use api::init_routes;
use allowed_hosts_middleware::AllowedHostsMiddleware;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("====================================");
    println!(" hyper-v-web-agent");
    println!(" a rust-based connector for hyper-v management.");
    println!("====================================");
    println!();

    if !running_as_admin() {
        println!("You are not running as administrator. Please relaunch with admin privileges.");
        let _ = std::io::stdin().read_line(&mut String::new());
        process::exit(1);
    }

    let config = load_or_create_config();
    let port = config.port.unwrap_or(7623);

    log_message("Starting hyper-v-web-agent...");

    // clone the config for use inside the app factory closure so we can still use the original later.
    let config_for_factory = config.clone();

    let app_factory = move || {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .max_age(3600),
            )
            .app_data(web::Data::new(config_for_factory.clone()))
            .configure(init_routes)
            .wrap(AllowedHostsMiddleware {
                allowed_hosts: config_for_factory.allowed_hosts.clone(),
            })
    };

    if let (Some(cert_path), Some(key_path)) =
        (config.ssl_certificate_path.clone(), config.ssl_certificate_key_path.clone())
    {
        println!(
            "Attempting to configure HTTPS with certificate '{}' and key '{}'",
            cert_path, key_path
        );
        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).map_err(|e| {
            eprintln!("Error creating SSL acceptor builder: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;
        builder.set_private_key_file(&key_path, SslFiletype::PEM).map_err(|e| {
            eprintln!("Error setting private key file '{}': {}", key_path, e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;
        builder.set_certificate_chain_file(&cert_path).map_err(|e| {
            eprintln!("Error setting certificate chain file '{}': {}", cert_path, e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        println!("Server listening on port {} over HTTPS.", port);
        println!(
            "Config loaded: agentconfig {{ ethernet_switch: \"{}\", iso_directory: \"{}\" }}",
            config.ethernet_switch, config.iso_directory
        );

        log_message("hyper-v-web-agent starting on specified port with SSL...");

        HttpServer::new(app_factory)
            .bind_openssl(("0.0.0.0", port), builder)?
            .run()
            .await
    } else {
        println!("Server listening on port {} over HTTP.", port);
        println!(
            "Config loaded: agentconfig {{ ethernet_switch: \"{}\", iso_directory: \"{}\" }}",
            config.ethernet_switch, config.iso_directory
        );

        log_message("hyper-v-web-agent starting on specified port (no SSL)...");

        HttpServer::new(app_factory)
            .bind(("0.0.0.0", port))?
            .run()
            .await
    }
}
