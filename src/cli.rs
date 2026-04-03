use clap::Parser;

#[derive(Parser, Debug)]
pub struct CliArgs {
    /// max hops allowed
    #[arg(long = "max-hub")]
    max_hubs: Option<u32>,
    /// the host to traceroute to ...
    host: String,
}

impl CliArgs {
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn max_hubs(&self) -> Option<u32> {
        self.max_hubs
    }
}

pub fn parse_cli_args() -> CliArgs {
    CliArgs::parse()
}
