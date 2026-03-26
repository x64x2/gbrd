use std::{
	collections::HashMap,
	net::{Ipv4Addr, Ipv6Addr, SocketAddr},
	path::PathBuf,
	time::Duration,
};

use clap::Parser;
use educe::Educe;
use figment::{
	Figment,
	providers::{Format, Serialized, Toml, Yaml},
};
use figment_json5::Json5;
use rand::{RngExt, distr::Alphanumeric, rng};
use serde::{Deserialize, Serialize};
use tracing::{level_filters::LevelFilter, warn};
use uuid::Uuid;

#[cfg(test)]
use crate::acl::{AclAddress, AclPorts};
use crate::{
	acl::AclRule,
	utils::{CongestionController, StackPrefer},
};

#[derive(Debug, Clone, Default)]
pub struct EnvState {
	pub in_docker:          bool,
	pub quic_force_toml:    bool,
	pub quic_config_format: Option<String>,
}

impl EnvState {
	pub fn from_system() -> Self {
		Self {
			in_docker:          std::env::var("IN_DOCKER").unwrap_or_default().to_lowercase() == "true",
			quic_force_toml:    std::env::var("quic_FORCE_TOML").is_ok(),
			quic_config_format: std::env::var("quic_CONFIG_FORMAT").ok().map(|v| v.to_lowercase()),
		}
	}
}

#[derive(Debug)]
pub struct Control(&'static str);

impl std::fmt::Display for Control {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::error::Error for Control {}
#[derive(Parser, Debug)]
#[command(name = "quic-server")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
	#[arg(short, long, value_name = "PATH")]
	pub config: Option<PathBuf>,

	#[arg(short, long, value_name = "DIR")]
	pub dir: Option<PathBuf>,

	#[arg(short, long)]
	pub init: bool,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
	pub log_level: LogLevel,
	#[educe(Default(expression = "[::]:8443".parse().unwrap()))]
	pub server:    SocketAddr,
	pub users:     HashMap<Uuid, String>,
	pub tls:       TlsConfig,

	#[educe(Default = "")]
	pub data_dir: PathBuf,

	#[educe(Default = None)]
	pub restful: Option<RestfulConfig>,

	pub quic: QuicConfig,

	#[educe(Default = true)]
	pub udp_relay_ipv6: bool,

	#[educe(Default = false)]
	pub zero_rtt_handshake: bool,

	#[educe(Default = true)]
	pub dual_stack: bool,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(3)))]
	pub auth_timeout: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(3)))]
	pub task_negotiation_timeout: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(10)))]
	pub gc_interval: Duration,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(30)))]
	pub gc_lifetime: Duration,

	#[educe(Default = 1500)]
	pub max_external_packet_size: usize,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(60)))]
	pub stream_timeout: Duration,

	#[serde(default)]
	pub outbound: OutboundConfig,

	#[serde(default, deserialize_with = "crate::acl::deserialize_acl")]
	#[educe(Default(expression = Vec::new()))]
	pub acl: Vec<AclRule>,

	pub experimental: ExperimentalConfig,

	#[serde(default, rename = "self_sign")]
	#[deprecated]
	pub __self_sign:          Option<bool>,
	#[serde(default, rename = "certificate")]
	#[deprecated]
	pub __certificate:        Option<PathBuf>,
	#[serde(default, rename = "private_key")]
	#[deprecated]
	pub __private_key:        Option<PathBuf>,
	#[serde(default, rename = "auto_ssl")]
	#[deprecated]
	pub __auto_ssl:           Option<bool>,
	#[serde(default, rename = "hostname")]
	#[deprecated]
	pub __hostname:           Option<String>,
	#[serde(default, rename = "acme_email")]
	#[deprecated]
	pub __acme_email:         Option<String>,
	#[serde(default, rename = "congestion_control")]
	#[deprecated]
	pub __congestion_control: Option<CongestionController>,
	#[serde(default, rename = "alpn")]
	#[deprecated]
	pub __alpn:               Option<Vec<String>>,
	#[serde(default, rename = "max_idle_time", with = "humantime_serde")]
	#[deprecated]
	pub __max_idle_time:      Option<Duration>,
	#[serde(default, rename = "initial_window")]
	#[deprecated]
	pub __initial_window:     Option<u64>,
	#[serde(default, rename = "receive_window")]
	#[deprecated]
	pub __send_window:        Option<u64>,
	#[serde(default, rename = "send_window")]
	#[deprecated]
	pub __receive_window:     Option<u32>,
	#[serde(default, rename = "initial_mtu")]
	#[deprecated]
	pub __initial_mtu:        Option<u16>,
	#[serde(default, rename = "min_mtu")]
	#[deprecated]
	pub __min_mtu:            Option<u16>,
	#[serde(default, rename = "gso")]
	#[deprecated]
	pub __gso:                Option<bool>,
	#[serde(default, rename = "pmtu")]
	#[deprecated]
	pub __pmtu:               Option<bool>,
	#[serde(rename = "restful_server")]
	#[deprecated]
	pub __restful_server:     Option<SocketAddr>,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
	pub self_sign:   bool,
	#[educe(Default(expression = ""))]
	pub certificate: PathBuf,
	#[educe(Default(expression = ""))]
	pub private_key: PathBuf,
	#[educe(Default(expression = Vec::new()))]
	pub alpn:        Vec<String>,
	#[educe(Default(expression = "localhost"))]
	pub hostname:    String,
	#[educe(Default(expression = false))]
	pub auto_ssl:    bool,
	#[educe(Default(expression = ""))]
	pub acme_email:  String,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfig {
	pub congestion_control: CongestionControlConfig,

	#[educe(Default = 1200)]
	pub initial_mtu: u16,

	#[educe(Default = 1200)]
	pub min_mtu: u16,

	#[educe(Default = true)]
	pub gso: bool,

	#[educe(Default = true)]
	pub pmtu: bool,

	#[educe(Default = 16777216)]
	pub send_window: u64,

	#[educe(Default = 8388608)]
	pub receive_window: u32,

	#[serde(with = "humantime_serde")]
	#[educe(Default(expression = Duration::from_secs(30)))]
	pub max_idle_time: Duration,
}

#[derive(Deserialize, Serialize, Educe, Clone, Debug)]
#[educe(Default)]
pub struct OutboundConfig 
{
	#[serde(default)]
	pub default: OutboundRule,

	#[serde(flatten)]
	pub named: std::collections::HashMap<String, OutboundRule>,
}

#[derive(Deserialize, Serialize, Educe, Clone, Debug)]
#[educe(Default)]
#[serde(deny_unknown_fields)]
pub struct OutboundRule {
	#[educe(Default = "direct".to_string())]
	#[serde(rename = "type")]
	pub kind: String,

	#[educe(Default(expression = Some(StackPrefer::V4first)))]
	pub ip_mode: Option<StackPrefer>,

	#[serde(default)]
	pub bind_ipv4: Option<Ipv4Addr>,

	#[serde(default)]
	pub bind_ipv6: Option<Ipv6Addr>,

	#[serde(default)]
	pub bind_device: Option<String>,

	#[serde(default)]
	pub addr: Option<String>,

	#[serde(default)]
	pub username: Option<String>,

	#[serde(default)]
	pub password: Option<String>,

	#[serde(default)]
	pub allow_udp: Option<bool>,
}

#[derive(Deserialize, Serialize, Educe)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct CongestionControlConfig {
	pub controller:     CongestionController,
	#[educe(Default = 1048576)]
	pub initial_window: u64,
}

#[derive(Deserialize, Serialize, Educe, Clone)]
#[educe(Default)]
#[serde(default, deny_unknown_fields)]
pub struct RestfulConfig {
	#[educe(Default(expression = "127.0.0.1:8443".parse().unwrap()))]
	pub addr:                     SocketAddr,
	#[educe(Default = "YOUR_SECRET_HERE")]
	pub secret:                   String,
	#[educe(Default = 0)]
	pub maximum_clients_per_user: usize,
}

#[derive(Deserialize, Serialize, Educe, Clone)]
#[educe(Default)]
#[serde(default)]
pub struct ExperimentalConfig {
	#[educe(Default = true)]
	pub drop_loopback: bool,
	#[educe(Default = true)]
	pub drop_private:  bool,
}

fn generate_random_alphanumeric_string(min: usize, max: usize) -> String {
	let mut rng = rng();
	let len = rng.random_range(min..=max);

	rng.sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

impl Config {
	pub fn migrate(&mut self) {
		#[allow(deprecated)]
		{
			if let Some(self_sign) = self.__self_sign {
				self.tls.self_sign = self_sign;
			}
			if let Some(certificate) = self.__certificate.take() {
				self.tls.certificate = certificate;
			}
			if let Some(private_key) = self.__private_key.take() {
				self.tls.private_key = private_key;
			}
			if let Some(auto_ssl) = self.__auto_ssl {
				self.tls.auto_ssl = auto_ssl;
			}
			if let Some(hostname) = self.__hostname.take() {
				self.tls.hostname = hostname;
			}
			if let Some(acme_email) = self.__acme_email.take() {
				self.tls.acme_email = acme_email;
			}
			if let Some(alpn) = self.__alpn.take() {
				self.tls.alpn = alpn;
			}
		}

		#[allow(deprecated)]
		{
			if let Some(congestion_control) = self.__congestion_control {
				self.quic.congestion_control.controller = congestion_control;
			}
			if let Some(max_idle_time) = self.__max_idle_time {
				self.quic.max_idle_time = max_idle_time;
			}
			if let Some(initial_window) = self.__initial_window {
				self.quic.congestion_control.initial_window = initial_window;
			}
			if let Some(send_window) = self.__send_window {
				self.quic.send_window = send_window;
			}
			if let Some(receive_window) = self.__receive_window {
				self.quic.receive_window = receive_window;
			}
			if let Some(initial_mtu) = self.__initial_mtu {
				self.quic.initial_mtu = initial_mtu;
			}
			if let Some(min_mtu) = self.__min_mtu {
				self.quic.min_mtu = min_mtu;
			}
			if let Some(gso) = self.__gso {
				self.quic.gso = gso;
			}
			if let Some(pmtu) = self.__pmtu {
				self.quic.pmtu = pmtu;
			}
		}

		#[allow(deprecated)]
		{
			if let Some(restful_server) = self.__restful_server {
				if self.restful.is_none() {
					self.restful = Some(RestfulConfig::default());
				}
				if let Some(ref mut restful) = self.restful {
					restful.addr = restful_server;
				}
			}
		}
	}

	pub fn full_example() -> Self {
		Self {
			users: {
				let mut users = HashMap::new();
				for _ in 0..5 {
					users.insert(Uuid::new_v4(), generate_random_alphanumeric_string(30, 50));
				}
				users
			},
			restful: Some(RestfulConfig {
				secret: generate_random_alphanumeric_string(30, 50),
				..Default::default()
			}),
			outbound: OutboundConfig {
				default: OutboundRule {
					kind: "direct".into(),
					ip_mode: Some(StackPrefer::V4first),
					..Default::default()
				},
				..Default::default()
			},
			acl: Vec::new(),
			..Default::default()
		}
	}
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Educe)]
#[educe(Default)]
pub enum LogLevel {
	Trace,
	Debug,
	#[educe(Default)]
	Info,
	Warn,
	Error,
	Off,
}
impl From<LogLevel> for LevelFilter {
	fn from(value: LogLevel) -> Self {
		match value {
			LogLevel::Trace => LevelFilter::TRACE,
			LogLevel::Debug => LevelFilter::DEBUG,
			LogLevel::Info => LevelFilter::INFO,
			LogLevel::Warn => LevelFilter::WARN,
			LogLevel::Error => LevelFilter::ERROR,
			LogLevel::Off => LevelFilter::OFF,
		}
	}
}

fn infer_config_format(content: &str) -> ConfigFormat {
	let trimmed = content.trim_start();

	if trimmed.starts_with('{') || trimmed.starts_with('[') {
		return ConfigFormat::Json;
	}

	if trimmed.starts_with("---") || trimmed.starts_with("%YAML") {
		return ConfigFormat::Yaml;
	}

	let lines: Vec<&str> = content
		.lines()
		.filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
		.collect();
	let has_yaml_patterns = lines.iter().any(|line| {
		let trimmed_line = line.trim();
		if trimmed_line.starts_with("- ") {
			return true;
		}
		if let Some(colon_pos) = trimmed_line.find(':') {
			let after_colon = &trimmed_line[colon_pos + 1..];
			return after_colon.is_empty() || after_colon.starts_with(' ') || after_colon.starts_with('\t');
		}
		false
	});

	let has_toml_patterns = lines.iter().any(|line| {
		let trimmed_line = line.trim();
		trimmed_line.starts_with('[') && trimmed_line.contains(']') && !trimmed_line.contains(':') || trimmed_line.contains('=')
	});

	if has_toml_patterns && !has_yaml_patterns {
		ConfigFormat::Toml
	} else if has_yaml_patterns && !has_toml_patterns {
		ConfigFormat::Yaml
	} else if has_toml_patterns && has_yaml_patterns {
		ConfigFormat::Toml
	} else {
		ConfigFormat::Unknown
	}
}

enum ConfigFormat {
	Json,
	Toml,
	Yaml,
	Unknown,
}

async fn find_config_in_dir(dir: &PathBuf) -> eyre::Result<PathBuf> {
	if !dir.exists() {
		return Err(eyre::eyre!("Directory not found: {}", dir.display()));
	}

	if !dir.is_dir() {
		return Err(eyre::eyre!("Path is not a directory: {}", dir.display()));
	}

	let mut entries = tokio::fs::read_dir(dir).await?;
	let mut config_files = Vec::new();

	while let Some(entry) = entries.next_entry().await? {
		let path = entry.path();
		if path.is_file() {
			if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
				match ext.to_lowercase().as_str() {
					"toml" | "json" | "json5" | "yaml" | "yml" => {
						config_files.push(path);
					}
					_ => {}
				}
			}
		}
	}

	if config_files.is_empty() {
		return Err(eyre::eyre!(
			"No recognizable config file found in directory: {}",
			dir.display()
		));
	}

	config_files.sort();

	Ok(config_files[0].clone())
}

pub async fn parse_config(cli: Cli, env_state: EnvState) -> eyre::Result<Config> {
	if cli.init {
		warn!("Generating an example configuration to config.toml......");

		let example = Config::full_example();
		let example = toml::to_string_pretty(&example).unwrap();

		let default_path = std::path::Path::new("config.toml");
		if tokio::fs::try_exists(default_path).await? {
			return Err(eyre::eyre!(
				"config.toml already exists in the current directory, aborting to avoid overwriting."
			));
		}

		tokio::fs::write(default_path, example).await?;
		return Err(Control("Done").into());
	}

	let cfg_path = if let Some(config) = cli.config {
		config
	} else if let Some(dir) = cli.dir {
		find_config_in_dir(&dir).await?
	} else {
		return Err(eyre::eyre!(
			"Config file is required. Use -c/--config to specify the path, -d/--dir to specify a directory, or -h for help."
		));
	};

	if !cfg_path.exists() {
		return Err(eyre::eyre!("Config file not found: {}", cfg_path.display()));
	}

	let figmet = Figment::from(Serialized::defaults(Config::default()));
	let format;

	if env_state.quic_force_toml {
		format = ConfigFormat::Toml;
	} else if let Some(ref env_format) = env_state.quic_config_format {

		match env_format.to_lowercase().as_str() {
			"json" | "json5" => {
				format = ConfigFormat::Json;
			}
			"yaml" | "yml" => {
				format = ConfigFormat::Yaml;
			}
			"toml" => {
				format = ConfigFormat::Toml;
			}
			_ => format = ConfigFormat::Unknown,
		}
	} else if env_state.in_docker {
		format = ConfigFormat::Unknown;
	} else {
		match cfg_path
			.extension()
			.and_then(|v| v.to_str())
			.unwrap_or_default()
			.to_lowercase()
			.as_str()
		{
			"json" | "json5" => {
				format = ConfigFormat::Json;
			}
			"yaml" | "yml" => {
				format = ConfigFormat::Yaml;
			}
			"toml" => {
				format = ConfigFormat::Toml;
			}
			_ => format = ConfigFormat::Unknown,
		}
	}
	let figmet = match format {
		ConfigFormat::Json => figmet.merge(Json5::file(&cfg_path)),
		ConfigFormat::Toml => figmet.merge(Toml::file(&cfg_path)),
		ConfigFormat::Yaml => figmet.merge(Yaml::file(&cfg_path)),
		ConfigFormat::Unknown => {
			let content = tokio::fs::read_to_string(&cfg_path).await?;
			let inferred_format = infer_config_format(&content);

			match inferred_format {
				ConfigFormat::Json => figmet.merge(Json5::file(&cfg_path)),
				ConfigFormat::Toml => figmet.merge(Toml::file(&cfg_path)),
				ConfigFormat::Yaml => figmet.merge(Yaml::file(&cfg_path)),
				ConfigFormat::Unknown => {
					return Err(Control(
						"Cannot infer config format from file extension or content, please set quic_CONFIG_FORMAT or \
						 quic_FORCE_TOML",
					))?;
				}
			}
		}
	};

	let mut config: Config = figmet.extract()?;
	config.migrate();

	if config.data_dir.to_str() == Some("") {
		config.data_dir = std::env::current_dir()?
	} else if config.data_dir.is_relative() {
		config.data_dir = std::env::current_dir()?.join(config.data_dir);
		tokio::fs::create_dir_all(&config.data_dir).await?;
	} else {
		tokio::fs::create_dir_all(&config.data_dir).await?;
	};

	let base_dir = config.data_dir.clone();
	config.tls.certificate = if config.tls.auto_ssl && config.tls.certificate.to_str() == Some("") {
		config.data_dir.join(format!("{}.cer.pem", config.tls.hostname))
	} else if config.tls.certificate.is_relative() {
		config.data_dir.join(&config.tls.certificate)
	} else {
		config.tls.certificate.clone()
	};

	config.tls.private_key = if config.tls.auto_ssl && config.tls.private_key.to_str() == Some("") {
		config.data_dir.join(format!("{}.key.pem", config.tls.hostname))
	} else if config.tls.private_key.is_relative() {
		base_dir.join(&config.tls.private_key)
	} else {
		config.tls.private_key.clone()
	};

	Ok(config)
}

#[cfg(test)]
mod tests {
	use std::{
		env, fs,
		net::{Ipv6Addr, SocketAddr, SocketAddrV6},
	};

	use tempfile::tempdir;

	use super::*;
	use crate::acl::{AclPortSpec, AclProtocol};

	async fn test_parse_config(config_content: &str, extension: &str) -> eyre::Result<Config> {
		test_parse_config_with_env(config_content, extension, EnvState::default()).await
	}

	async fn test_parse_config_with_env(config_content: &str, extension: &str, env_state: EnvState) -> eyre::Result<Config> {
		let temp_dir = tempdir().unwrap();
		let config_path = temp_dir.path().join(format!("config{}", extension));

		fs::write(&config_path, config_content).unwrap();

		let os_args = vec![
			"test_binary".to_owned(),
			"--config".to_owned(),
			config_path.to_string_lossy().into_owned(),
		];

		let cli = Cli::try_parse_from(os_args)?;
		parse_config(cli, env_state).await
	}
	#[tokio::test]
	async fn test_valid_toml_config() -> eyre::Result<()> {
		let config = include_str!("../tests/config/valid_toml_config.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.log_level, LogLevel::Warn);
		assert_eq!(result.server, "127.0.0.1:8080".parse().unwrap());
		assert!(!result.udp_relay_ipv6);
		assert!(result.zero_rtt_handshake);

		assert!(result.tls.self_sign);
		assert!(result.tls.auto_ssl);
		assert_eq!(result.tls.hostname, "testhost");
		assert_eq!(result.tls.acme_email, "admin@example.com");
		assert_eq!(result.quic.initial_mtu, 1400);
		assert_eq!(result.quic.min_mtu, 1300);
		assert_eq!(result.quic.send_window, 10000000);
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		assert_eq!(result.quic.congestion_control.initial_window, 2000000);

		let restful = result.restful.unwrap();
		assert_eq!(restful.addr, "192.168.1.100:8081".parse().unwrap());
		assert_eq!(restful.secret, "test_secret");
		assert_eq!(restful.maximum_clients_per_user, 5);

		let uuid1 = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
		let uuid2 = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174001").unwrap();
		assert_eq!(result.users.get(&uuid1), Some(&"password1".to_string()));
		assert_eq!(result.users.get(&uuid2), Some(&"password2".to_string()));
		let _ = tokio::fs::remove_dir_all("__test__custom_data").await;
		Ok(())
	}

	#[tokio::test]
	async fn test_json_config() {
		let config = include_str!("../tests/config/json_config.json");

		let result = test_parse_config(config, ".json").await.unwrap();

		assert_eq!(result.log_level, LogLevel::Error);
		assert_eq!(
			result.server,
			SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0))
		);

		let uuid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174002").unwrap();
		assert_eq!(result.users.get(&uuid), Some(&"old_password".to_string()));

		assert!(!result.tls.self_sign);
		assert!(result.data_dir.ends_with("__test__legacy_data")); 
		let _ = tokio::fs::remove_dir_all("__test__legacy_data").await;
	}

	#[tokio::test]
	async fn test_path_handling() {
		let config = include_str!("../tests/config/path_handling.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		let current_dir = env::current_dir().unwrap();

		assert_eq!(result.data_dir, current_dir.join("__test__relative_path"));

		assert_eq!(
			result.tls.certificate,
			current_dir.join("__test__relative_path").join("certs/server.crt")
		);
		assert_eq!(
			result.tls.private_key,
			current_dir.join("__test__relative_path").join("certs/server.key")
		);

		let _ = tokio::fs::remove_dir_all("__test__relative_path").await;
	}

	#[tokio::test]
	async fn test_auto_ssl_path_generation() {
		let config = include_str!("../tests/config/auto_ssl_path_generation.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		let expected_cert = env::current_dir()
			.unwrap()
			.join("__test__ssl_data")
			.join("example.com.cer.pem");

		let expected_key = env::current_dir()
			.unwrap()
			.join("__test__ssl_data")
			.join("example.com.key.pem");

		assert_eq!(result.tls.certificate, expected_cert);
		assert_eq!(result.tls.private_key, expected_key);

		let _ = tokio::fs::remove_dir_all("__test__ssl_data").await;
	}

	#[tokio::test]
	async fn test_error_handling() {
		let config = "invalid toml content";
		let result = test_parse_config(config, ".toml").await;
		assert!(result.is_err());

		let config = "{ invalid json }";
		let result = test_parse_config(config, ".json").await;
		assert!(result.is_err());

		let result = Cli::try_parse_from(vec!["test_binary", "--config", "non_existent.toml"]);
		if let Ok(cli) = result {
			assert!(cli.config.is_some());
			assert!(!cli.config.unwrap().exists());
		}

		let result = Cli::try_parse_from(vec!["test_binary"]);
		assert!(result.is_ok());
		let cli = result.unwrap();
		assert!(cli.config.is_none());
	}

	#[tokio::test]
	async fn test_outbound_no_configuration() {
		let config = include_str!("../tests/config/outbound_no_configuration.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.outbound.default.kind, "direct");
		assert_eq!(result.outbound.named.len(), 0);
	}

	#[tokio::test]
	async fn test_outbound_valid_with_default() {
		let config = include_str!("../tests/config/outbound_valid_with_default.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.outbound.default.kind, "direct");
		assert_eq!(result.outbound.named.len(), 2);

		let prefer_v4 = result.outbound.named.get("prefer_v4").unwrap();
		assert_eq!(prefer_v4.kind, "direct");
		assert_eq!(prefer_v4.ip_mode, Some(StackPrefer::V4first));
		assert_eq!(prefer_v4.bind_ipv4, Some("2.4.6.8".parse().unwrap()));
		assert_eq!(prefer_v4.bind_device, Some("eth233".to_string()));

		let socks5 = result.outbound.named.get("through_socks5").unwrap();
		assert_eq!(socks5.kind, "socks5");
		assert_eq!(socks5.addr, Some("127.0.0.1:1080".to_string()));
		assert_eq!(socks5.username, Some("optional".to_string()));
		assert_eq!(socks5.password, Some("optional".to_string()));
	}

	#[tokio::test]
	async fn test_outbound_with_legacy_ip_mode_aliases() {
		let config = include_str!("../tests/config/outbound_with_legacy_ip_mode_aliases.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.outbound.default.ip_mode, Some(StackPrefer::V4first));

		let prefer_v6 = result.outbound.named.get("prefer_v6_rule").unwrap();
		assert_eq!(prefer_v6.ip_mode, Some(StackPrefer::V6first));

		let only_v4 = result.outbound.named.get("only_v4_rule").unwrap();
		assert_eq!(only_v4.ip_mode, Some(StackPrefer::V4only));

		let only_v6 = result.outbound.named.get("only_v6_rule").unwrap();
		assert_eq!(only_v6.ip_mode, Some(StackPrefer::V6only));
	}

	#[tokio::test]
	async fn test_acl_parsing() {
		let config = include_str!("../tests/config/acl_parsing.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.acl.len(), 10);

		let rule1 = &result.acl[0];
		assert_eq!(rule1.outbound, "allow");
		assert_eq!(rule1.addr, AclAddress::Localhost);
		assert!(rule1.ports.is_some());
		let ports1 = rule1.ports.as_ref().unwrap();
		assert_eq!(ports1.entries.len(), 1);
		assert_eq!(ports1.entries[0].protocol, Some(AclProtocol::Udp));
		assert_eq!(ports1.entries[0].port_spec, AclPortSpec::Single(53));
		assert!(rule1.hijack.is_none());

		let rule2 = &result.acl[1];
		assert_eq!(rule2.outbound, "allow");
		assert_eq!(rule2.addr, AclAddress::Localhost);
		let ports2 = rule2.ports.as_ref().unwrap();
		assert_eq!(ports2.entries.len(), 4);

		let rule4 = &result.acl[3];
		assert_eq!(rule4.outbound, "reject");
		assert_eq!(rule4.addr, AclAddress::Cidr("10.6.0.0/16".to_string()));

		let rule6 = &result.acl[5];
		assert_eq!(rule6.outbound, "allow");
		assert_eq!(rule6.addr, AclAddress::WildcardDomain("*.google.com".to_string()));

		let rule10 = &result.acl[9];
		assert_eq!(rule10.outbound, "default");
		assert_eq!(rule10.addr, AclAddress::Ip("8.8.4.4".to_string()));
		assert!(rule10.ports.is_some());
		assert_eq!(rule10.hijack, Some("1.1.1.1".to_string()));
	}

	#[tokio::test]
	async fn test_acl_parsing_edge_cases() {
		use serde::de::value::StrDeserializer;

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("localhost")).unwrap();
		assert_eq!(addr, AclAddress::Localhost);

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("*.example.com")).unwrap();
		assert_eq!(addr, AclAddress::WildcardDomain("*.example.com".to_string()));

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("192.168.1.0/24")).unwrap();
		assert_eq!(addr, AclAddress::Cidr("192.168.1.0/24".to_string()));

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("127.0.0.1")).unwrap();
		assert_eq!(addr, AclAddress::Ip("127.0.0.1".to_string()));

		let addr: AclAddress =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("example.com")).unwrap();
		assert_eq!(addr, AclAddress::Domain("example.com".to_string()));

		let ports: AclPorts =
			serde::Deserialize::deserialize(StrDeserializer::<serde::de::value::Error>::new("80,443,1000-2000,udp/53"))
				.unwrap();
		assert_eq!(ports.entries.len(), 4);
		assert_eq!(ports.entries[0].port_spec, AclPortSpec::Single(80));
		assert_eq!(ports.entries[2].port_spec, AclPortSpec::Range(1000, 2000));
		assert_eq!(ports.entries[3].protocol, Some(AclProtocol::Udp));

		let rule = crate::acl::parse_acl_rule("allow google.com 80,443").unwrap();
		assert_eq!(rule.outbound, "allow");
		assert_eq!(rule.addr, AclAddress::Domain("google.com".to_string()));
		assert!(rule.ports.is_some());
		assert!(rule.hijack.is_none());
	}

	#[tokio::test]
	async fn test_default_values() {
		let config = include_str!("../tests/config/default_values.toml");
		let result = test_parse_config(config, ".toml").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "[::]:8443".parse().unwrap());
		assert!(result.udp_relay_ipv6);
		assert!(!result.zero_rtt_handshake);
		assert!(result.dual_stack);
		assert_eq!(result.auth_timeout, Duration::from_secs(3));
		assert_eq!(result.task_negotiation_timeout, Duration::from_secs(3));
		assert_eq!(result.gc_interval, Duration::from_secs(10));
		assert_eq!(result.gc_lifetime, Duration::from_secs(30));
		assert_eq!(result.max_external_packet_size, 1500);
		assert_eq!(result.stream_timeout, Duration::from_secs(60));
	}
	#[tokio::test]
	async fn test_invalid_uuid() {
		let config = include_str!("../tests/config/invalid_uuid.toml");

		let result = test_parse_config(config, ".toml").await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_invalid_socket_addr() {
		let config = include_str!("../tests/config/invalid_socket_addr.toml");

		let result = test_parse_config(config, ".toml").await;
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn test_duration_parsing() {
		let config = include_str!("../tests/config/duration_parsing.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();

		assert_eq!(result.auth_timeout, Duration::from_secs(5));
		assert_eq!(result.task_negotiation_timeout, Duration::from_secs(10));
		assert_eq!(result.gc_interval, Duration::from_secs(30));
		assert_eq!(result.gc_lifetime, Duration::from_secs(60));
		assert_eq!(result.stream_timeout, Duration::from_secs(120));
	}

	#[tokio::test]
	async fn test_empty_acl() {
		let config = include_str!("../tests/config/empty_acl.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();
		assert_eq!(result.acl.len(), 0);
	}

	#[tokio::test]
	async fn test_acl_comments_and_whitespace() {
		let config = include_str!("../tests/config/acl_comments_and_whitespace.toml");

		let result = test_parse_config(config, ".toml").await.unwrap();
		assert_eq!(result.acl.len(), 3);
	}

	#[tokio::test]
	async fn test_congestion_control_variants() {
		let config_bbr = include_str!("../tests/config/congestion_control_bbr.toml");

		let result = test_parse_config(config_bbr, ".toml").await.unwrap();
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		let config_new_reno = include_str!("../tests/config/congestion_control_newreno.toml");

		let result = test_parse_config(config_new_reno, ".toml").await.unwrap();
		assert_eq!(result.quic.congestion_control.controller, CongestionController::NewReno);
	}

	#[tokio::test]
	async fn test_backward_compatibility_standard_json() {
		let json_config = include_str!("../tests/config/backward_compatibility_standard_json.json");

		let result = test_parse_config(json_config, ".json").await;
		assert!(result.is_ok(), "Standard JSON should be parseable by JSON5");
	}
	#[tokio::test]
	async fn test_legacy_field_migration_json() {
		let config = include_str!("../tests/config/legacy_field_migration_json.json");
		let result = test_parse_config(config, ".json").await.unwrap();

		assert!(result.tls.self_sign);
		assert!(result.tls.certificate.ends_with("cert.pem"));
		assert!(result.tls.private_key.ends_with("key.pem"));
		assert_eq!(result.tls.hostname, "example.com");
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		assert_eq!(result.quic.max_idle_time, Duration::from_secs(60));
		assert_eq!(result.quic.initial_mtu, 1500);
		assert!(result.restful.is_some());
		assert_eq!(result.restful.unwrap().addr, "0.0.0.0:8080".parse().unwrap());
	}

	#[tokio::test]
	async fn test_infer_format_toml_without_extension() {
		let config = include_str!("../tests/config/infer_format_toml_without_extension");
		let result = test_parse_config(config, "").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "127.0.0.1:8080".parse().unwrap());
	}

	#[tokio::test]
	async fn test_infer_format_json_without_extension() {
		let config = include_str!("../tests/config/infer_format_json_without_extension");
		let result = test_parse_config(config, "").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Debug);
		assert_eq!(result.server, "0.0.0.0:8443".parse().unwrap());
	}

	#[tokio::test]
	async fn test_yaml_config_format() {
		let config = include_str!("../tests/config/yaml_config_format.yaml");
		let result = test_parse_config(config, ".yaml").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Warn);
		assert_eq!(result.server, "127.0.0.1:9000".parse().unwrap());
		assert_eq!(result.tls.hostname, "yaml.test.com");
	}

	#[tokio::test]
	async fn test_json5_with_comments() {
		let config = include_str!("../tests/config/json5_with_comments.json5");
		let result = test_parse_config(config, ".json5").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "127.0.0.1:8080".parse().unwrap());
		assert_eq!(result.tls.hostname, "test.json5.com");
	}

	#[tokio::test]
	async fn test_json5_with_trailing_commas() {
		let config = include_str!("../tests/config/json5_with_trailing_commas.json5");
		let result = test_parse_config(config, ".json5").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Debug);
		assert_eq!(
			result.server,
			SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0))
		);
		assert_eq!(result.users.len(), 2);
	}

	#[tokio::test]
	async fn test_json5_with_unquoted_keys() {
	
		let config = include_str!("../tests/config/json5_with_unquoted_keys.json5");
		let result = test_parse_config(config, ".json5").await.unwrap();
		assert_eq!(result.log_level, LogLevel::Warn);
		assert_eq!(result.server, "0.0.0.0:8443".parse().unwrap());
		assert_eq!(result.tls.hostname, "unquoted.test.com");
	}

	#[tokio::test]
	async fn test_json5_comprehensive_features() {
		let config = include_str!("../tests/config/json5_comprehensive_features.json5");
		let result = test_parse_config(config, ".json5").await.unwrap();

		assert_eq!(result.log_level, LogLevel::Info);
		assert_eq!(result.server, "127.0.0.1:9443".parse().unwrap());
		assert!(!result.udp_relay_ipv6);
		assert!(result.zero_rtt_handshake);

		assert_eq!(result.users.len(), 2);

		assert!(result.tls.self_sign);
		assert!(result.tls.auto_ssl);
		assert_eq!(result.tls.hostname, "json5.example.com");
		assert_eq!(result.quic.initial_mtu, 1400);
		assert_eq!(result.quic.min_mtu, 1300);
		assert_eq!(result.quic.send_window, 8000000);
		assert_eq!(result.quic.congestion_control.controller, CongestionController::Bbr);
		assert_eq!(result.quic.congestion_control.initial_window, 1500000);

		let restful = result.restful.unwrap();
		assert_eq!(restful.addr, "127.0.0.1:8888".parse().unwrap());
		assert_eq!(restful.secret, "json5_secret");
		assert_eq!(restful.maximum_clients_per_user, 10);
	}

	#[tokio::test]
	async fn test_json5_with_acl_rules() {
		let config = include_str!("../tests/config/json5_with_acl_rules.json5");
		let result = test_parse_config(config, ".json5").await.unwrap();

		assert_eq!(result.acl.len(), 4);
	}
}
