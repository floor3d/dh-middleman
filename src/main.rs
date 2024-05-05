use clap::{App, Arg};
use rand::Rng;
use std::io::Result;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

struct CryptoParams {
    a: u32,
    g: u32,
    p: u32,
    gamodp: u32,
    sharedkey: u32,
}

impl CryptoParams {
    fn new(a: u32) -> Self {
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

    fn compute_gamodp(g: u32, a: u32, p: u32) -> u32 {
        (g.pow(a as u32)) % p
    }

    fn update_shared_key(&mut self, new_key: u32) {
        self.sharedkey = new_key;
    }
}

fn parse_port() -> String {
    let matches = App::new("My App")
        .version("1.0")
        .author("Evan Defloor")
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
        .get_matches();

    matches
        .value_of("port")
        .unwrap()
        .parse()
        .expect("Invalid port format")
}

#[tokio::main]
async fn main() -> Result<()> {
    let port = parse_port();
    let mut rng = rand::thread_rng(); // Get a random number generator
    let rand: u32 = rng.gen(); // Generate a random u32
    let params = CryptoParams::new(rand);

    let ip = format!("127.0.0.1:{}", port);
    let mut stream = TcpStream::connect(ip).await?;

    let mut rng = rand::thread_rng();
    let random_duration = rng.gen_range(Duration::from_secs(1)..Duration::from_secs(6));

    let mut string = String::new();
    // Set up the timer and the listening part.
    tokio::select! {
        _ = sleep(random_duration) => {
            // Timer finished first, send a message.
            println!("Timer ended. Sending a message.");
            let msg = "Hello from client!";
            tokio::io::AsyncWriteExt::write_all(&mut stream, msg.as_bytes()).await?;
        }
        result = tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut string) => {
            match result {
                Ok(_) => {
                    // Message received before the timer ended.
                    println!("Message received first, not sending.");
                }
                Err(e) => println!("Failed to receive message: {:?}", e),
            }
        }
    }

    Ok(())
}
