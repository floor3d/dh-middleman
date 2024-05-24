use anyhow::Result;
use clap::{App, Arg};
use rand::Rng;
use serde::{Deserialize, Serialize};
// use serde_json::json;
use num_traits::pow;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{self, Duration};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Message {
    message_type: String,
    data: String,
}
#[derive(Debug)]
struct CryptoParams {
    a: u64,
    g: u64,
    p: u64,
    gamodp: u64,
    sharedkey: u64,
}

impl Message {
    fn new(message_type: String, data: String) -> Self {
        Message { message_type, data }
    }
}
impl CryptoParams {
    fn new(a: u64) -> Self {
        let g = 5;
        let p = 23;
        let gamodp = Self::compute_gamodp(g, a, p);
        let sharedkey = 0;
        CryptoParams {
            a,
            g,
            p,
            gamodp,
            sharedkey,
        }
    }

    fn compute_gamodp(g: u64, a: u64, p: u64) -> u64 {
        (g.pow(a as u32)) % p
    }

    fn update_shared_key(&mut self, new_key: u64) {
        self.sharedkey = new_key;
        println!("[+] Shared key updated to {}", new_key);
    }
}

fn parse_port(port: &mut String, partner_port: &mut String) {
    let matches = App::new("My App")
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

async fn send_verifier(stream: &mut TcpStream, params: &CryptoParams) {
    let msg_type = String::from("VERIFY");
    let data = "Please verify me".to_owned();
    let msg = Message::new(msg_type, data);
    send_message(stream, &msg).await;
    listen(stream, params).await;
}

// update shared key and send gamodp and verifier, then verify, then pass execution
// to listener
async fn handle_shared_key(
    stream: &mut TcpStream,
    params: &mut CryptoParams,
    partner_msg: &Message,
) {
    let partner_data: Result<u64, std::num::ParseIntError> = partner_msg.data.parse();
    let mut partner_gamodp: u64 = 0;
    match partner_data {
        Ok(number) => partner_gamodp = number,
        Err(_) => println!("Failed to parse the input as u64"),
    }
    let shared_key: u64 = pow(partner_gamodp, params.a as usize);
    params.update_shared_key(shared_key);
    send_verifier(stream, params).await;
}

//TODO
// naively verify shared key
fn verify_shared_key(stream: TcpStream, params: &CryptoParams) -> bool {
    return true;
}

// handle message
async fn handle(stream: &mut TcpStream, params: &CryptoParams, message: &Message) {
    // let serialized = serde_json::to_string(message).unwrap();
    // match stream.write_all(serialized.as_bytes()).await {
    //     Ok(_) => {}
    //     Err(_) => {
    //         println!("Message failed to send! \n {:?}", message)
    //     }
    // }
    if message.message_type == "VERIFY" {
        println!("I have verified this shit");
        let mut return_msg = message.clone();
        return_msg.message_type = "VERIFY2".to_owned();
        send_message(stream, &return_msg).await;
    } else if message.message_type == "VERIFY2" {
        println!("I have verified this shit");
        let mut return_msg = message.clone();
        return_msg.message_type = "COMM".to_owned();
        return_msg.data =
            "Hello we hath verified and now are on to normal communication".to_owned();
        send_message(stream, &return_msg).await;
        println!("Sent verify2 message");
    } else if message.message_type == "COMM" {
        println!("[+] Received normal communication message");
        println!("{:?}", message);
    }
}

async fn listen(stream: &mut TcpStream, params: &CryptoParams) {
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
                //TODO: add parse and respond
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
    parse_port(&mut port, &mut partner_port);
    let mut rng = rand::thread_rng(); // Get a random number generator
    let rand: u64 = rng.gen_range(2..15); // Generate a random u64
    let mut params = CryptoParams::new(rand);

    let ip = format!("127.0.0.1:{}", port);
    let partner_ip = format!("127.0.0.1:{}", partner_port);
    let mut rng = rand::thread_rng();
    // sleep for 5 or more seconds, which gives time for the attacker to impersonate one of them
    let timeout_duration = rng.gen_range(Duration::from_secs(5)..Duration::from_secs(15));
    println!("Listening for {:?} seconds...", timeout_duration);

    let listener = TcpListener::bind(ip).await?;
    println!("Listening on port {}", port);
    let msg_type = String::from("HELLO");
    let data = format!("{}", params.gamodp);
    let msg = Message::new(msg_type, data);
    let serialized = serde_json::to_string(&msg).unwrap();
    tokio::select! {
        // Handle incoming connections
        Ok((mut stream, _)) = listener.accept() => {
            println!("Received a connection");
            // tokio::spawn(async move {
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
            // });
        }
        // Timeout block
        _ = time::sleep(timeout_duration) => {
            println!("Timeout reached!");
            println!("Sending data to {}!", partner_ip);
            if let Ok(mut stream) = TcpStream::connect(partner_ip).await {
                println!("Connected");
                stream.write_all(serialized.as_bytes()).await?;
                println!("Sent!");
                listen(&mut stream, &params).await;
            } else {
                println!("Failed to connect");
            }
        }
    }
    println!("Ok we done");
    Ok(())
}
