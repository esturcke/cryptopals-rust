use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use tokio::task;

#[macro_use]
extern crate lazy_static;

mod bytes;
mod challenge1;
mod challenge10;
mod challenge11;
mod challenge12;
mod challenge13;
mod challenge14;
mod challenge15;
mod challenge16;
mod challenge17;
mod challenge18;
mod challenge19;
mod challenge2;
mod challenge20;
mod challenge21;
mod challenge22;
mod challenge23;
mod challenge24;
mod challenge25;
mod challenge26;
mod challenge27;
mod challenge28;
mod challenge29;
mod challenge3;
mod challenge30;
mod challenge31;
mod challenge32;
mod challenge33;
mod challenge34;
mod challenge4;
mod challenge5;
mod challenge6;
mod challenge7;
mod challenge8;
mod challenge9;

mod crack;
mod crypt;
mod english;
mod rand;

use std::fs;

async fn solve(server: actix_web::dev::Server) {
  let _ = tokio::join!(
    task::spawn(challenge1::solve()),
    task::spawn(challenge2::solve()),
    task::spawn(challenge3::solve()),
    task::spawn(challenge4::solve()),
    task::spawn(challenge5::solve()),
    task::spawn(challenge6::solve(&VANILLA)),
    task::spawn(challenge7::solve(&VANILLA)),
    task::spawn(challenge8::solve()),
    task::spawn(challenge9::solve()),
    task::spawn(challenge10::solve(&VANILLA)),
    task::spawn(challenge11::solve()),
    task::spawn(challenge12::solve(&ICE_ICE_BABY)),
    task::spawn(challenge13::solve()),
    task::spawn(challenge14::solve(&ICE_ICE_BABY)),
    task::spawn(challenge15::solve()),
    task::spawn(challenge16::solve()),
    task::spawn(challenge17::solve()),
    task::spawn(challenge18::solve()),
    task::spawn(challenge19::solve()),
    task::spawn(challenge20::solve(&FURY)),
    task::spawn(challenge21::solve()),
    task::spawn(challenge22::solve()),
    task::spawn(challenge23::solve()),
    task::spawn(challenge24::solve()),
    task::spawn(challenge25::solve()),
    task::spawn(challenge26::solve()),
    task::spawn(challenge27::solve()),
    task::spawn(challenge28::solve()),
    task::spawn(challenge29::solve()),
    task::spawn(challenge30::solve()),
    task::spawn(challenge31::solve()),
    task::spawn(challenge32::solve()),
    task::spawn(challenge33::solve()),
    task::spawn(challenge34::solve())
  );

  server.stop(false).await
}

#[actix_web::main]
pub async fn main() {
  #[get("/31-hmac/{file}/{signature}")]
  async fn hmac(path: web::Path<(String, String)>) -> impl Responder {
    let (file, signature) = path.into_inner();
    if challenge31::check(file, signature).await {
      HttpResponse::Ok()
    } else {
      HttpResponse::InternalServerError()
    }
  }

  #[get("/32-hmac/{file}/{signature}")]
  async fn hmac2(path: web::Path<(String, String)>) -> impl Responder {
    let (file, signature) = path.into_inner();
    if challenge32::check(file, signature).await {
      HttpResponse::Ok()
    } else {
      HttpResponse::InternalServerError()
    }
  }

  let server = HttpServer::new(|| App::new().service(hmac).service(hmac2))
    .bind("127.0.0.1:9000")
    .unwrap()
    .run();

  let _ = tokio::join!(task::spawn(server.clone()), solve(server));
}

lazy_static! {
  static ref VANILLA: String = fs::read_to_string("data/play-that-funky-music.txt").unwrap();
  static ref ICE_ICE_BABY: String = fs::read_to_string("data/ice-ice-baby.txt").unwrap();
  static ref FURY: String = fs::read_to_string("data/fury.txt").unwrap();
}
