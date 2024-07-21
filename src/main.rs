extern crate aes;
extern crate block_modes;
extern crate block_padding;
extern crate num_bigint;
extern crate rand;

use std::thread;
use std::collections::HashMap;
use crate::rand::Rng;
use aes::Aes256;
use anyhow::Result;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Ecb};
use clap::{App, Arg};
use num_bigint::{BigInt, RandBigInt};
use num_traits::Num;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{self, Duration};

type Aes256Ecb = Ecb<Aes256, Pkcs7>;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Message {
    identity: String,
    message_type: String,
    data: String,
    encrypted_data: Vec<u8>,
}
#[derive(Clone)]
struct CryptoParams {
    a: BigInt,
    g: BigInt,
    p: BigInt,
    gamodp: BigInt,
    sharedkey: Option<Vec<u8>>,
    identity: String,
}

struct Peer {
    peer_identity: String,
    peer_stream: &mut TcpStream,
    peer_params: CryptoParams
}

struct AttackerData {
    peers: Vec<Peer>,
}


impl Message {
    fn new(identity: String, message_type: String, data: String) -> Self {
        let encrypted_data: Vec<u8> = Vec::new();
        Message {
            identity,
            message_type,
            data,
            encrypted_data,
        }
    }
}
impl CryptoParams {
    fn new(identity: String) -> Self {
        let p = BigInt::parse_bytes(b"23", 10).unwrap();
        let g = BigInt::parse_bytes(b"5", 10).unwrap();
        let mut rng = rand::thread_rng(); // Get a random number generator
        let a = rng.gen_bigint_range(&BigInt::from(1), &p);
        let gamodp = g.modpow(&a, &p);
        let sharedkey = None;
        CryptoParams {
            a,
            g,
            p,
            gamodp,
            sharedkey,
            identity
        }
    }

    fn update_shared_key(&mut self, new_key: Vec<u8>) {
        self.sharedkey = Some(new_key);
        println!("[+] Shared key updated");
        println!("{:?}", self.sharedkey);
    }

    fn encrypt(&mut self, data: &str) -> Vec<u8> {
        if let Some(key) = &self.sharedkey {
            let k = Aes256Ecb::new_from_slices(&key, Default::default()).unwrap();
            return k.encrypt_vec(data.as_bytes()).clone();
        } else {
            println!("shared key is None");
            return Vec::new();
        }
    }

    fn decrypt(&mut self, ciphertext: &Vec<u8>) -> String {
        if let Some(key) = &self.sharedkey {
            let k = Aes256Ecb::new_from_slices(&key, Default::default()).unwrap();
            return std::str::from_utf8(&k.decrypt_vec(ciphertext).unwrap())
                .unwrap()
                .to_owned()
                .clone();
        } else {
            println!("shared key is None");
            return String::new();
        }
    }
}

impl AttackerData {
    // Create a new AttackerData instance
    fn new() -> Self {
        let peers: Vec<Peer> = Vec::new();
        AttackerData {
            peers
        }
    }
}

fn parse_port(port: &mut String, partner_port: &mut String, identity: &mut String) {
    let matches = App::new("DH MITM")
        .version("1.0")
        .author("Evan")
        .about("Uses port")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .help("Sets the port to use")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("partner_port")
                .short('P')
                .long("partner_port")
                .value_name("PARTNER_PORT")
                .help("Sets the partner port to use")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("identity")
                .short('i')
                .long("identity")
                .value_name("IDENTITY")
                .help("Sets identity of user")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    *port = matches
        .value_of("port")
        .unwrap()
        .parse()
        .expect("Invalid port format");
    *partner_port = matches
        .value_of("partner_port")
        .unwrap()
        .parse()
        .expect("Invalid port format");
    *identity = matches
        .value_of("identity")
        .unwrap()
        .parse()
        .expect("Invalid identity");
}

async fn send_message(stream: &mut TcpStream, message: &Message) {
    let serialized = serde_json::to_string(message).unwrap();
    match stream.write_all(serialized.as_bytes()).await {
        Err(_) => {
            println!("Failed to send message!");
        }
        Ok(_) => {
            println!("Sent message:");
            println!("{:?}", message);
        }
    }
}

// We have created our shared key. Now, we need to give them our gamodp so they can calc it too
async fn send_key_agreement(stream: &mut TcpStream, params: &mut CryptoParams) {
    let msg_type = String::from("AGREE");
    let data = format!("{}", params.gamodp);

    let msg = Message::new(params.identity.clone(), msg_type, data);
    send_message(stream, &msg).await;
    listen(stream, params).await;
}

async fn calc_and_update_shared_key(
    params: &mut CryptoParams,
    partner_msg: &Message,
) {
    let partner_gamodp = BigInt::from_str_radix(&partner_msg.data, 10)
        .expect("Failed to parse BigInt from partner msg");
    let shared_secret = partner_gamodp.modpow(&params.a, &params.p);
    let shared_secret_bytes = shared_secret.to_bytes_be().1;

    let key_bytes = {
        let mut key = [0u8; 32];
        let len = shared_secret_bytes.len().min(32);
        key[..len].copy_from_slice(&shared_secret_bytes[..len]);
        key
    };

    let key = key_bytes.to_vec();
    params.update_shared_key(key);
}

// update shared key and send gamodp and verifier, then verify, then pass execution
// to listener
async fn handle_shared_key(
    stream: &mut TcpStream,
    params: &mut CryptoParams,
    partner_msg: &Message,
) {
    calc_and_update_shared_key(params, partner_msg).await;
    send_key_agreement(stream, params).await;
}

//TODO
// naively verify shared key
fn verify_shared_key(_params: &mut CryptoParams, _message: &Message) -> bool {
    return true;
}

// handle message
async fn handle(stream: &mut TcpStream, params: &mut CryptoParams, message: &Message) {
    if message.message_type == "AGREE" {
        println!("Received AGREE Message, calculating shared key");
        calc_and_update_shared_key(params, message).await;
        let data = String::new();
        let return_msg = Message::new(params.identity.clone(), "VERIFY".to_owned(), data);
        send_message(stream, &return_msg).await;
    } else if message.message_type == "VERIFY" {
        if !verify_shared_key(params, message) {
            println!("Failed to verify shared key. Screw that message!");
            return;
        }
        println!("I have verified this lowkey");
        let msg_data = String::new();
        let mut return_msg = Message::new(params.identity.clone(), "COMM".to_owned(), msg_data);
        let data = "Hello we hath verified and now are on to normal communication".to_owned();
        return_msg.encrypted_data = params.encrypt(&data).to_vec();
        send_message(stream, &return_msg).await;
    } else if message.message_type == "COMM" {
        println!("[+] Received communication message");
        let msg = params.decrypt(&message.encrypted_data);
        println!("Decrypted message: {}", msg);
        thread::sleep(Duration::from_secs(2));
        let msg_data = String::new();
        let mut return_msg = Message::new(params.identity.clone(), "COMM".to_owned(), msg_data);
        let data = "Yoooooo we comming for real".to_owned();
        return_msg.encrypted_data = params.encrypt(&data).to_vec();
        send_message(stream, &return_msg).await;
    }
}

async fn listen(stream: &mut TcpStream, params: &mut CryptoParams) {
    let mut buffer = [0; 1024];
    println!("I'm finna listen now");
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                // Connection closed by client
                println!("Client disconnected!");
                break;
            }
            Ok(bytes_read) => {
                // Process the received message
                let received_message = &buffer[..bytes_read];
                println!("Received: {}", String::from_utf8_lossy(received_message));
                let message: Message = serde_json::from_slice(&buffer[..bytes_read])
                    .expect("Failed to deserialize message");
                handle(stream, params, &message).await;
            }
            Err(e) => {
                eprintln!("Error reading from client: {}", e);
                break;
            }
        }
    }
    println!("Ok we are done listening lol");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut port: String = String::new();
    let mut partner_port: String = String::new();
    let mut identity: String = String::new();
    parse_port(&mut port, &mut partner_port, &mut identity);
    if identity.eq_ignore_ascii_case("Attacker") {
        let attacker_data: AttackerData = AttackerData::new();
        return;
    }
    let mut params = CryptoParams::new(identity);
    let mut rng = thread_rng();

    let ip = format!("127.0.0.1:{}", port);
    let partner_ip = format!("127.0.0.1:{}", partner_port);
    let timeout_duration = rng.gen_range(Duration::from_secs(3)..Duration::from_secs(8));

    println!("Listening for {:?} seconds...", timeout_duration);

    let listener = TcpListener::bind(ip).await?;
    println!("Listening on port {}", port);
    tokio::select! {
        // Handle incoming connections
        Ok((mut stream, _)) = listener.accept() => {
            println!("Received a connection");
            let mut buf = [0; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(0) => 1,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("failed to read from socket; err = {:?}", e);
                    return Ok(());
                }
            };
            if n == 1 {
                println!("WTF JUST HAPPENED");
            }
            let deserialized: Message = serde_json::from_slice(&buf[..n]).expect("Failed to deserialize message");
            println!("{:?}", deserialized);
            // update shared key and send gamodp and verifier, then verify, then pass execution
            // to listener
            handle_shared_key(&mut stream, &mut params, &deserialized).await;
        }
        // Timeout block
        _ = time::sleep(timeout_duration) => {
            println!("Timeout reached!");
            println!("Sending data to {}!", partner_ip);
            let msg_type = String::from("HELLO");
            let data = format!("{}", params.gamodp);
            let msg = Message::new(params.identity.clone(), msg_type, data);
            let serialized = serde_json::to_string(&msg).unwrap();
            if let Ok(mut stream) = TcpStream::connect(partner_ip).await {
                println!("Connected");
                stream.write_all(serialized.as_bytes()).await?;
                println!("Sent!");
                listen(&mut stream, &mut params).await;
            } else {
                println!("Failed to connect");
            }
        }
    }
    println!("Ok we done");
    Ok(())
}
