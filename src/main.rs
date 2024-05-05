use clap::{App, Arg};
use rand::Rng;
use std::io::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{self, Duration};

struct CryptoParams {
    a: u64,
    g: u64,
    p: u64,
    gamodp: u64,
    sharedkey: u64,
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

#[tokio::main]
async fn main() -> Result<()> {
    let mut port: String = String::new();
    let mut partner_port: String = String::new();
    parse_port(&mut port, &mut partner_port);
    let mut rng = rand::thread_rng(); // Get a random number generator
    let rand: u64 = rng.gen_range(2..20); // Generate a random u64
    let params = CryptoParams::new(rand);

    let ip = format!("127.0.0.1:{}", port);
    let partner_ip = format!("127.0.0.1:{}", port);
    let mut rng = rand::thread_rng();
    // sleep for 5 or more seconds, which gives time for the attacker to impersonate one of them
    let timeout_duration = rng.gen_range(Duration::from_secs(5)..Duration::from_secs(15));

    let listener = TcpListener::bind(ip).await?;
    println!("Listening on port {}", port);

    tokio::select! {
        // Handle incoming connections
        Ok((mut socket, _)) = listener.accept() => {
            println!("Received a connection");
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                loop {
                    let n = match socket.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("failed to read from socket; err = {:?}", e);
                            return;
                        }
                    };

                    if let Err(e) = socket.write_all(&buf[0..n]).await {
                        eprintln!("failed to write to socket; err = {:?}", e);
                        return;
                    }
                }
            });
        }
        // Timeout block
        _ = time::sleep(timeout_duration) => {
            println!("Timeout reached");
            if let Ok(mut stream) = TcpStream::connect(partner_ip).await {
                println!("Connected");
                stream.write_all(b"Hello!").await?;
            } else {
                println!("Failed to connect");
            }
        }
    }

    Ok(())
}
