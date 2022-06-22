// teleport, Copyright (c) 2022, Maximilian Burke
// This file is distributed under the FreeBSD(-ish) license.
// See LICENSE.TXT for details

use http::StatusCode;
use warp::reply::Response;
use warp::Reply;

#[derive(Debug)]
pub(crate) enum Error {
    Internal(Box<dyn std::error::Error>),
    WithStatusCode(StatusCode, &'static str),
    InvalidId,
    AlreadyInitialized,
    SecretNotFound,
    InvalidData,
}

impl Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::WithStatusCode(code, _) => *code,
            Error::InvalidId => StatusCode::BAD_REQUEST,
            Error::SecretNotFound => StatusCode::NOT_FOUND,
            Error::InvalidData => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn msg(&self) -> String {
        match self {
            Error::Internal(e) => e.to_string(),
            Error::WithStatusCode(_, msg) => (*msg).to_owned(),
            Error::InvalidId => "Invalid ID specified".to_owned(),
            Error::AlreadyInitialized => "Already initialized".to_owned(),
            Error::SecretNotFound => {
                "Secret not found! Either claim link is incorrect or it has already been claimed."
                    .to_owned()
            }
            Error::InvalidData => "Data submitted was invalid, unable to decode".to_owned(),
        }
    }
}

impl From<zip::result::ZipError> for Error {
    fn from(e: zip::result::ZipError) -> Self {
        Self::Internal(e.into())
    }
}

impl From<warp::Error> for Error {
    fn from(e: warp::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Internal(e.into())
    }
}

impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Self::Internal(e.into())
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Self::Internal(e.into())
    }
}

fn error_page(code: StatusCode, msg: String) -> String {
    use std::collections::HashMap;

    use crate::{render_template, Template};

    let parameters = HashMap::from([
        ("title", format!("Error {}", code.as_u16())),
        ("message", msg),
    ]);
    render_template(Template::Error, parameters)
}

impl From<Error> for Response {
    fn from(e: Error) -> Response {
        let code = e.status_code();
        if code == StatusCode::INTERNAL_SERVER_ERROR {
            let body = warp::reply::html(error_page(
                code,
                "A server error has happened; please try again.".into(),
            ));
            error!("{}", e.msg());

            warp::reply::with_status(body, code).into_response()
        } else {
            let body = warp::reply::html(error_page(code, e.msg()));
            warp::reply::with_status(body, code).into_response()
        }
    }
}
