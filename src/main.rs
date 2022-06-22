// teleport, Copyright (c) 2022, Maximilian Burke
// This file is distributed under the FreeBSD(-ish) license.
// See LICENSE.TXT for details

mod error;
mod passphrase;
mod store;

use futures::StreamExt;
use http::StatusCode;
use once_cell::sync::OnceCell;
use serde_derive::Deserialize;
use std::collections::HashMap;
use warp::reply::Response;
use warp::{Buf, Filter, Reply};

use crate::error::Error;
use crate::store::{retrieve, serialize_file_map, serialize_secret, write, Value};

#[macro_use]
extern crate log;

const TEXT: &str = "text";
const DEFAULT_MAX_STRING_LENGTH: usize = 4096;
const DEFAULT_MAX_FILE_SIZE: usize = 262_144;

fn default_max_string_length() -> usize {
    DEFAULT_MAX_STRING_LENGTH
}

fn default_max_file_size() -> usize {
    DEFAULT_MAX_FILE_SIZE
}

#[derive(Eq, Hash, PartialEq)]
enum Template {
    Index,
    Claim,
    Claimed,
    Retrieve,
    Error,
}

#[derive(Deserialize)]
struct Config {
    data_dir: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    port: u16,
    #[serde(default = "default_max_string_length")]
    max_secret_length: usize,
    #[serde(default = "default_max_file_size")]
    total_file_size: usize,
    #[serde(default)]
    deny_files: bool,
}

pub(crate) static CONFIG: OnceCell<Config> = OnceCell::new();
static PAGE_TEMPLATES: OnceCell<HashMap<Template, &'static str>> = OnceCell::new();

fn render_template(template: Template, parameters: HashMap<&str, String>) -> String {
    // A stupid simple version of moustache templates.
    let mut page = (*PAGE_TEMPLATES.get().unwrap().get(&template).unwrap()).to_string();

    for (key, value) in parameters {
        let needle = format!("{{{{{}}}}}", key);
        page = page.replace(&needle, &value);
    }

    page
}

fn render_retrieval_page(key: String, code: String) -> Result<Response, Error> {
    let parameters = HashMap::from([("key", key), ("code", code)]);
    let page = render_template(Template::Retrieve, parameters);
    let response =
        warp::reply::with_status(warp::reply::html(page), StatusCode::OK).into_response();

    Ok(response)
}

fn form_post_data_handler_impl(data: HashMap<String, String>) -> Result<Response, Error> {
    let data = data.get(TEXT).ok_or(Error::WithStatusCode(
        StatusCode::BAD_REQUEST,
        "Request is missing text field",
    ))?;

    let max_secret_length = {
        let c = CONFIG.get().unwrap();
        c.max_secret_length
    };

    if data.len() > max_secret_length {
        return Err(Error::WithStatusCode(
            StatusCode::BAD_REQUEST,
            "Data exceeds server's maximum data length",
        ));
    }

    let serialized_data = serialize_secret(data)?;
    let (key, code) = write(&serialized_data)?;
    render_retrieval_page(key, code)
}

#[allow(clippy::unused_async)]
async fn form_post_data_handler(
    data: HashMap<String, String>,
) -> Result<Response, warp::Rejection> {
    match form_post_data_handler_impl(data) {
        Ok(r) => Ok(r),
        Err(e) => Ok(e.into()),
    }
}

async fn multipart_post_data_handler_impl(
    mut form_data: warp::multipart::FormData,
) -> Result<Response, Error> {
    let mut file_map = Vec::new();

    let total_file_size = {
        let c = CONFIG.get().unwrap();
        c.total_file_size
    };

    while let Some(part) = form_data.next().await {
        let part = part?;
        let mut data = Vec::new();

        let filename = if let Some(f) = part.filename() {
            f
        } else {
            "unnamed"
        }
        .to_owned();
        let mut stream = part.stream();
        while let Some(buf) = stream.next().await {
            let buf = buf?;
            data.extend(buf.chunk());
        }

        if data.len() > total_file_size {
            return Err(Error::WithStatusCode(
                StatusCode::BAD_REQUEST,
                "File exceeds server's maximum file size",
            ));
        }

        file_map.push((filename, data));
    }

    let serialized_data = serialize_file_map(&file_map)?;
    let (key, code) = write(&serialized_data)?;
    render_retrieval_page(key, code)
}

async fn multipart_post_data_handler(
    form_data: warp::multipart::FormData,
) -> Result<Response, warp::Rejection> {
    match multipart_post_data_handler_impl(form_data).await {
        Ok(r) => Ok(r),
        Err(e) => Ok(e.into()),
    }
}

fn claim_data_get_handler_impl(id: String) -> Result<Response, Error> {
    let parameters = HashMap::from([("id", id)]);
    let page = render_template(Template::Claim, parameters);
    let response =
        warp::reply::with_status(warp::reply::html(page), StatusCode::OK).into_response();

    Ok(response)
}

#[allow(clippy::unused_async)]
async fn claim_data_get_handler(id: String) -> Result<Response, warp::Rejection> {
    match claim_data_get_handler_impl(id) {
        Ok(r) => Ok(r),
        Err(e) => Ok(e.into()),
    }
}

fn validate_id(id: &str) -> Result<(), Error> {
    for c in id.chars() {
        match c {
            'a'..='f' | '0'..='9' => continue,
            _ => return Err(Error::InvalidId),
        }
    }

    Ok(())
}

async fn claim_data_post_handler_impl(
    id: String,
    data: HashMap<String, String>,
) -> Result<Response, Error> {
    let code = data.get("code").ok_or(Error::WithStatusCode(
        StatusCode::BAD_REQUEST,
        "No code specified",
    ))?;

    validate_id(&id)?;

    let value = retrieve(&id, code).await?;

    match value {
        Value::Secret(secret) => {
            let byte_serialize = form_urlencoded::byte_serialize(secret.as_bytes());
            let secret = byte_serialize.collect::<String>();
            let parameters = HashMap::from([("secret", secret)]);
            let page = render_template(Template::Claimed, parameters);
            let response =
                warp::reply::with_status(warp::reply::html(page), StatusCode::OK).into_response();

            Ok(response)
        }
        Value::File {
            name,
            data,
            content_type,
        } => warp::http::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", content_type)
            .header(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", name),
            )
            .body(data.into())
            .map_err(|err| Error::Internal(err.into())),
    }
}

async fn claim_data_post_handler(
    id: String,
    data: HashMap<String, String>,
) -> Result<Response, warp::Rejection> {
    match claim_data_post_handler_impl(id, data).await {
        Ok(r) => Ok(r),
        Err(e) => Ok(e.into()),
    }
}

fn static_data_handler_impl(tail: warp::path::Tail) -> Result<Response, Error> {
    const FILES: &[(&str, &[u8], &str)] = &[
        (
            "GitHub-Mark-Light-64px.png",
            include_bytes!("../assets/static/GitHub-Mark-Light-64px.png"),
            "image/png",
        ),
        (
            "teleport.css",
            include_bytes!("../assets/static/teleport.css"),
            "text/css",
        ),
        (
            "favicon.ico",
            include_bytes!("../assets/static/favicon.ico"),
            "image/x-icon",
        ),
    ];

    let (content, mime) = match tail.as_str() {
        "" | "index.html" | "index.htm" => {
            let config = CONFIG.get().unwrap();

            let uploads_disabled = config.deny_files;

            let parameters = HashMap::from([
                ("secretSize", config.max_secret_length.to_string()),
                ("maxUploadSize", config.total_file_size.to_string()),
                (
                    "uploadsHeader",
                    if uploads_disabled {
                        "Uploads disabled :("
                    } else {
                        "Share Files"
                    }
                    .to_owned(),
                ),
                (
                    "disabledUploads",
                    if uploads_disabled {
                        "disabled".to_owned()
                    } else {
                        String::new()
                    },
                ),
            ]);

            let index = render_template(Template::Index, parameters)
                .as_bytes()
                .to_vec();
            (index, "text/html")
        }
        s => match FILES.iter().find(|c| c.0 == s) {
            Some(entry) => (entry.1.to_owned(), entry.2),
            None => {
                return Err(Error::WithStatusCode(
                    StatusCode::NOT_FOUND,
                    "Unable to find content",
                ))
            }
        },
    };

    warp::http::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", mime)
        .body(content.into())
        .map_err(|err| Error::Internal(err.into()))
}

async fn static_data_handler(tail: warp::path::Tail) -> Result<Response, warp::Rejection> {
    match static_data_handler_impl(tail) {
        Ok(r) => Ok(r),
        Err(e) => Ok(e.into()),
    }
}

async fn teleport_main() {
    use std::net::SocketAddr;

    let (total_file_size, port, deny_files, tls_cert, tls_key) = {
        let c = CONFIG.get().unwrap();
        (
            c.total_file_size,
            c.port,
            c.deny_files,
            c.tls_cert.clone(),
            c.tls_key.clone(),
        )
    };

    let form_post_data_handler = warp::post()
        .and(warp::path!("secret"))
        .and(warp::body::form())
        .and_then(form_post_data_handler);

    let multipart_post_data_handler = warp::post()
        .and(warp::path!("file"))
        .and(warp::multipart::form().max_length(total_file_size as u64))
        .and_then(multipart_post_data_handler);

    let claim_data_get_handler = warp::get()
        .and(warp::path!("claim" / String))
        .and_then(claim_data_get_handler);

    let claim_data_post_handler = warp::post()
        .and(warp::path!("claim" / String))
        .and(warp::body::form())
        .and_then(claim_data_post_handler);

    let static_data_handler = warp::get()
        .and(warp::path::tail())
        .and_then(static_data_handler);

    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    if deny_files {
        let routes = claim_data_get_handler
            .or(claim_data_post_handler)
            .or(form_post_data_handler)
            .or(static_data_handler);

        if let (Some(tls_cert), Some(tls_key)) = (tls_cert, tls_key) {
            warp::serve(routes)
                .tls()
                .cert_path(tls_cert)
                .key_path(tls_key)
                .run(addr)
                .await;
        } else {
            warp::serve(routes).run(addr).await;
        }
    } else {
        let routes = claim_data_get_handler
            .or(claim_data_post_handler)
            .or(form_post_data_handler)
            .or(multipart_post_data_handler)
            .or(static_data_handler);

        if let (Some(tls_cert), Some(tls_key)) = (tls_cert, tls_key) {
            warp::serve(routes)
                .tls()
                .cert_path(tls_cert)
                .key_path(tls_key)
                .run(addr)
                .await;
        } else {
            warp::serve(routes).run(addr).await;
        }
    }
}

fn init() -> Result<(), Error> {
    pretty_env_logger::init_timed();

    let config = std::env::var("TELEPORT_CONFIG")
        .expect("please set the TELEPORT_CONFIG env var to the Teleport configuration file!");

    let config_file = std::fs::read_to_string(config).expect("cannot read configuration file!");
    let config = toml::from_str::<Config>(&config_file).expect("cannot parse configuration file!");
    CONFIG.set(config).map_err(|_| Error::AlreadyInitialized)?;
    crate::store::init()
}

#[tokio::main]
async fn main() {
    init().unwrap();

    let index = include_str!("../assets/templates/index.html.template");
    let claim = include_str!("../assets/templates/claim.html.template");
    let claimed = include_str!("../assets/templates/claimed.html.template");
    let retrieve = include_str!("../assets/templates/retrieve.html.template");
    let error = include_str!("../assets/templates/error.html.template");

    let page_templates = [
        (Template::Index, index),
        (Template::Claim, claim),
        (Template::Claimed, claimed),
        (Template::Retrieve, retrieve),
        (Template::Error, error),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();
    let res = PAGE_TEMPLATES.set(page_templates);
    assert!(res.is_ok());

    teleport_main().await;
}
