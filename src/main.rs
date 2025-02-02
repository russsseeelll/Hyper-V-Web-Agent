// main starts the hyper-v-http-agent
mod allowed_hosts_middleware;
mod api;
mod commands;
mod config;
mod logging;
mod powershell;
mod validation;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use allowed_hosts_middleware::AllowedHostsMiddleware;
use api::init_routes;
use config::{load_or_create_config, running_as_admin};
use logging::log_message;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::process;



// loading or creating the config, and setting up the http or https server
#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("====================================");
    println!(" hyper-v-web-agent");
    println!(" a rust-based connector for hyper-v management.");
    println!("====================================");
    println!();

    // check if running as adminis
    if !running_as_admin() {
        println!("you are not running as administrator. please relaunch with admin privileges.");
        let _ = std::io::stdin().read_line(&mut String::new());
        process::exit(1);
    }

    // load config or create one interactively if needed
    let config = load_or_create_config();
    let port = config.port.unwrap_or(7623);

    log_message("starting hyper-v-web-agent...");

    // clone the config for use within the app factory closure
    let config_for_factory = config.clone();

    // define the app factory which sets up cors, routes and middleware
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

    // if ssl certificate and key are provided, configure the server to run over https
    if let (Some(cert_path), Some(key_path)) = (
        config.ssl_certificate_path.clone(),
        config.ssl_certificate_key_path.clone(),
    ) {
        println!(
            "attempting to configure https with certificate '{}' and key '{}'",
            cert_path, key_path
        );
        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls()).map_err(|e| {
            eprintln!("error creating ssl acceptor builder: {}", e);
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;
        builder
            .set_private_key_file(&key_path, SslFiletype::PEM)
            .map_err(|e| {
                eprintln!("error setting private key file '{}': {}", key_path, e);
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })?;
        builder
            .set_certificate_chain_file(&cert_path)
            .map_err(|e| {
                eprintln!(
                    "error setting certificate chain file '{}': {}",
                    cert_path, e
                );
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })?;

        println!("server listening on port {} over https.", port);
        println!(
            "config loaded: agentconfig {{ ethernet_switch: \"{}\", iso_directory: \"{}\" }}",
            config.ethernet_switch, config.iso_directory
        );

        log_message("hyper-v-web-agent starting on specified port with ssl...");

        HttpServer::new(app_factory)
            .bind_openssl(("0.0.0.0", port), builder)?
            .run()
            .await
    } else {
        // otherwise, run the server over http
        println!("server listening on port {} over http.", port);
        println!(
            "config loaded: agentconfig {{ ethernet_switch: \"{}\", iso_directory: \"{}\" }}",
            config.ethernet_switch, config.iso_directory
        );

        log_message("hyper-v-web-agent starting on specified port (no ssl)...");

        HttpServer::new(app_factory)
            .bind(("0.0.0.0", port))?
            .run()
            .await
    }
}
