//! Outbound-request (egress) guard against server-side request forgery.
//!
//! Any component that sends a request to a URL it did not choose itself — a
//! webhook endpoint registered by a tenant, a Web Push subscription endpoint
//! supplied by a browser, an HTTP client whose path comes from user input —
//! can be turned into a proxy for reaching the deployment's own network: the
//! cloud metadata service at `169.254.169.254`, a Redis bound to localhost, an
//! internal admin API on `10.x`. [`EgressPolicy`] is the shared guard for that
//! class of bug.
//!
//! The guard has three layers, and all three are needed:
//!
//! 1. **Literal checks** ([`EgressPolicy::check_url`]): scheme (https unless
//!    explicitly relaxed), a host must be present, IP-literal hosts must not be
//!    in any special-purpose range, and names under `localhost`, `.local`,
//!    `.internal` and `.home.arpa` are refused outright.
//! 2. **Resolve-all-then-reject** ([`EgressPolicy::resolve`] and the
//!    [`GuardedResolver`] installed by [`EgressPolicy::apply`]): a DNS name is
//!    resolved and the request is refused if *any* answer is internal. A name
//!    that points at `169.254.169.254` is the cheapest bypass of a literal-only
//!    check.
//! 3. **Pinning**: the connection must go to the addresses that were vetted,
//!    not to whatever a second lookup returns (DNS rebinding). Installing the
//!    [`GuardedResolver`] as reqwest's resolver achieves this by construction —
//!    the vetted answer *is* the answer the connector dials — and every new
//!    connection re-resolves and re-vets. [`EgressPolicy::apply`] also disables
//!    redirects (a 30x to the metadata service would otherwise be followed
//!    without re-running layer 1) and proxies (with a proxy configured the
//!    client resolves the *proxy*, so the guard never sees the target).
//!
//! IP-literal URLs never reach a resolver — the connector parses them directly
//! — which is why layer 1 must run on every request URL before it is sent.
//!
//! # Example
//!
//! ```rust,no_run
//! use armature_http_client::egress::EgressPolicy;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let policy = EgressPolicy::default();
//! let client = policy.apply(reqwest::Client::builder()).build()?;
//!
//! let url = url::Url::parse("https://hooks.example.com/notify")?;
//! policy.check_url(&url)?; // literal checks; DNS answers are vetted at connect
//! client.post(url).body("{}").send().await?;
//! # Ok(())
//! # }
//! ```

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use url::{Host, Url};

/// Default bound on a single DNS lookup made by the guard.
///
/// Lookups run on tokio's process-wide blocking pool; without a bound, a
/// hostname delegated to a non-responsive authoritative server holds a pool
/// thread for the resolver's full retry budget, and enough concurrent
/// requests to such names exhaust the pool.
pub const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Host-name suffixes refused before any lookup is attempted.
///
/// `.localhost` is reserved for loopback by RFC 6761, `.local` is mDNS,
/// `.internal` is what GCP (`metadata.google.internal`) and many private zones
/// use, and `.home.arpa` is RFC 8375 residential space.
const DEFAULT_DENIED_SUFFIXES: &[&str] = &[".localhost", ".local", ".internal", ".home.arpa"];

/// Why the egress guard refused a URL.
///
/// Messages never include the URL or host: the target is usually
/// attacker-influenced, and echoing it back invites log and error-message
/// injection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EgressError {
    /// The scheme is not allowed (only `https`, or `http` when explicitly
    /// permitted).
    SchemeNotAllowed,
    /// The URL has no host (e.g. `data:` or `file:` URLs).
    MissingHost,
    /// The host name is on the deny list (`.internal`, `.local`, ...).
    DeniedHostName,
    /// The host is an IP literal, or resolves to an address, in a
    /// loopback/private/link-local/reserved/special-purpose range.
    InternalAddress,
    /// The host name could not be resolved (lookup failure, empty answer, or
    /// the lookup exceeded the configured timeout).
    Unresolvable,
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::SchemeNotAllowed => "egress refused: URL scheme is not allowed",
            Self::MissingHost => "egress refused: URL has no host",
            Self::DeniedHostName => "egress refused: host name is not allowed",
            Self::InternalAddress => "egress refused: target is an internal address",
            Self::Unresolvable => "egress refused: host could not be resolved",
        };
        f.write_str(msg)
    }
}

impl StdError for EgressError {}

impl EgressError {
    /// Find an [`EgressError`] anywhere in an error's `source()` chain.
    ///
    /// When a [`GuardedResolver`] refuses a lookup, reqwest reports a generic
    /// connect error whose source chain carries the `EgressError`; this lets
    /// callers distinguish "blocked by policy" from "the network is down".
    pub fn find_in<'a>(err: &'a (dyn StdError + 'static)) -> Option<&'a EgressError> {
        let mut current: Option<&(dyn StdError + 'static)> = Some(err);
        while let Some(e) = current {
            if let Some(found) = e.downcast_ref::<EgressError>() {
                return Some(found);
            }
            current = e.source();
        }
        None
    }
}

/// Resolve a host name to socket addresses.
///
/// A seam so the guard can be driven by fixed answers in tests instead of the
/// ambient resolver. The production implementation is [`SystemResolver`].
#[async_trait]
pub trait HostResolver: Send + Sync {
    /// Resolve `host` as if connecting to it on `port`. An empty `Ok` is
    /// treated the same as an error.
    async fn lookup(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

/// The operating system resolver (`getaddrinfo` via `tokio::net::lookup_host`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

#[async_trait]
impl HostResolver for SystemResolver {
    async fn lookup(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// Outbound-request policy: which URLs a client may connect to.
///
/// The default policy is the strict one: https only, no loopback, no internal
/// or special-purpose addresses, no `localhost`/`.local`/`.internal` names.
/// Relaxations are explicit, named, and intended for development and tests.
///
/// See the [module documentation](self) for how the pieces fit together.
#[derive(Clone)]
pub struct EgressPolicy {
    allow_http: bool,
    allow_loopback: bool,
    denied_suffixes: Vec<String>,
    resolve_timeout: Duration,
    resolver: Arc<dyn HostResolver>,
}

impl fmt::Debug for EgressPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressPolicy")
            .field("allow_http", &self.allow_http)
            .field("allow_loopback", &self.allow_loopback)
            .field("denied_suffixes", &self.denied_suffixes)
            .field("resolve_timeout", &self.resolve_timeout)
            .finish_non_exhaustive()
    }
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allow_http: false,
            allow_loopback: false,
            denied_suffixes: DEFAULT_DENIED_SUFFIXES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            resolve_timeout: DEFAULT_RESOLVE_TIMEOUT,
            resolver: Arc::new(SystemResolver),
        }
    }
}

impl EgressPolicy {
    /// The strict default policy. Same as [`EgressPolicy::default`].
    pub fn strict() -> Self {
        Self::default()
    }

    /// Permit plain `http://` targets.
    ///
    /// Only for development against non-TLS stubs: without TLS, anyone on the
    /// path can read and rewrite the request, including any credentials or
    /// signatures it carries. The address checks still apply.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Permit loopback targets (`localhost`, `127.0.0.0/8`, `::1`), over
    /// http or https.
    ///
    /// Only for local integration tests against a stub bound to localhost. In
    /// a production binary this lets whoever controls the URL reach every
    /// service bound to the host's loopback interface. No other internal range
    /// is relaxed by this flag.
    pub fn allow_insecure_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    /// Refuse host names ending in `suffix` (compared case-insensitively; a
    /// leading `.` is added if missing) in addition to the defaults.
    pub fn deny_host_suffix(mut self, suffix: impl Into<String>) -> Self {
        let mut suffix = suffix.into().to_ascii_lowercase();
        if !suffix.starts_with('.') {
            suffix.insert(0, '.');
        }
        self.denied_suffixes.push(suffix);
        self
    }

    /// Bound each DNS lookup made by the guard (default
    /// [`DEFAULT_RESOLVE_TIMEOUT`]).
    pub fn resolve_timeout(mut self, timeout: Duration) -> Self {
        self.resolve_timeout = timeout;
        self
    }

    /// Replace the resolver (for deterministic tests, or a custom DNS stack).
    pub fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Whether plain `http://` is permitted.
    pub fn allows_http(&self) -> bool {
        self.allow_http
    }

    /// Whether loopback targets are permitted.
    pub fn allows_loopback(&self) -> bool {
        self.allow_loopback
    }

    /// Whether this policy permits connecting to `ip`.
    pub fn is_allowed_ip(&self, ip: IpAddr) -> bool {
        if self.allow_loopback && is_loopback_ip(ip) {
            return true;
        }
        !is_internal_ip(ip)
    }

    /// Literal checks on a URL: scheme, host presence, deny-listed names and
    /// IP-literal ranges.
    ///
    /// Run this on **every** URL before sending, including each redirect hop:
    /// IP-literal hosts are dialed directly and never pass through the
    /// [`GuardedResolver`]. A domain host that passes is *not* proven safe —
    /// its DNS answers are vetted by [`EgressPolicy::resolve`] or, at connect
    /// time, by the resolver installed with [`EgressPolicy::apply`].
    pub fn check_url(&self, url: &Url) -> Result<(), EgressError> {
        let host = url.host().ok_or(EgressError::MissingHost)?;

        let loopback = match &host {
            Host::Domain(d) => is_localhost_name(d),
            Host::Ipv4(ip) => is_loopback_ip(IpAddr::V4(*ip)),
            Host::Ipv6(ip) => is_loopback_ip(IpAddr::V6(*ip)),
        };
        if loopback {
            return if !self.allow_loopback {
                Err(EgressError::InternalAddress)
            } else if matches!(url.scheme(), "http" | "https") {
                Ok(())
            } else {
                Err(EgressError::SchemeNotAllowed)
            };
        }

        match url.scheme() {
            "https" => {}
            "http" if self.allow_http => {}
            _ => return Err(EgressError::SchemeNotAllowed),
        }

        match host {
            Host::Ipv4(ip) if !self.is_allowed_ip(IpAddr::V4(ip)) => {
                Err(EgressError::InternalAddress)
            }
            Host::Ipv6(ip) if !self.is_allowed_ip(IpAddr::V6(ip)) => {
                Err(EgressError::InternalAddress)
            }
            Host::Domain(name) if self.is_denied_name(name) => Err(EgressError::DeniedHostName),
            _ => Ok(()),
        }
    }

    /// Run [`EgressPolicy::check_url`], then resolve the host and vet every
    /// answer.
    ///
    /// Returns the vetted addresses (for an IP literal, just that address),
    /// suitable for `reqwest::ClientBuilder::resolve_to_addrs` when a caller
    /// wants to pin explicitly instead of installing the [`GuardedResolver`].
    pub async fn resolve(&self, url: &Url) -> Result<Vec<SocketAddr>, EgressError> {
        self.check_url(url)?;
        let port = url
            .port_or_known_default()
            .ok_or(EgressError::SchemeNotAllowed)?;
        match url.host().ok_or(EgressError::MissingHost)? {
            Host::Ipv4(ip) => Ok(vec![SocketAddr::new(IpAddr::V4(ip), port)]),
            Host::Ipv6(ip) => Ok(vec![SocketAddr::new(IpAddr::V6(ip), port)]),
            Host::Domain(name) => self.resolve_name(name, port).await,
        }
    }

    /// Resolve `host` and refuse it if *any* answer is not allowed.
    ///
    /// Rejecting on any rather than all is deliberate: with one public and one
    /// internal answer, which one gets dialed is up to the connector.
    pub async fn resolve_name(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, EgressError> {
        if is_localhost_name(host) {
            if !self.allow_loopback {
                return Err(EgressError::InternalAddress);
            }
        } else if self.is_denied_name(host) {
            return Err(EgressError::DeniedHostName);
        }

        let addrs = tokio::time::timeout(self.resolve_timeout, self.resolver.lookup(host, port))
            .await
            .map_err(|_elapsed| EgressError::Unresolvable)?
            .map_err(|_io| EgressError::Unresolvable)?;

        if addrs.is_empty() {
            return Err(EgressError::Unresolvable);
        }
        if addrs.iter().any(|a| !self.is_allowed_ip(a.ip())) {
            return Err(EgressError::InternalAddress);
        }
        Ok(addrs)
    }

    /// A reqwest DNS resolver that enforces this policy on every lookup.
    pub fn guarded_resolver(&self) -> GuardedResolver {
        GuardedResolver {
            policy: self.clone(),
        }
    }

    /// Harden a reqwest client builder for untrusted targets.
    ///
    /// Installs the [`GuardedResolver`] (every new connection re-resolves and
    /// re-vets, and dials only vetted addresses), disables redirects, disables
    /// proxies (including `HTTP(S)_PROXY` from the environment), and sets
    /// `https_only` unless http or loopback was explicitly permitted.
    /// Callers that need redirects must install their own
    /// `reqwest::redirect::Policy` *after* this call and run
    /// [`EgressPolicy::check_url`] on every hop.
    ///
    /// Do not combine with `resolve`/`resolve_to_addrs` overrides for
    /// untrusted names: reqwest consults those before the resolver.
    pub fn apply(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        builder
            .dns_resolver(Arc::new(self.guarded_resolver()))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(!self.allow_http && !self.allow_loopback)
    }

    fn is_denied_name(&self, name: &str) -> bool {
        let name = normalize_name(name);
        name == "localhost"
            || self
                .denied_suffixes
                .iter()
                .any(|suffix| name.ends_with(suffix.as_str()) || name == suffix[1..])
    }
}

/// A `reqwest` DNS resolver that refuses names resolving to internal
/// addresses. Created by [`EgressPolicy::guarded_resolver`].
#[derive(Debug, Clone)]
pub struct GuardedResolver {
    policy: EgressPolicy,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0: reqwest substitutes the URL's port (or the scheme
            // default) into every returned address.
            match policy.resolve_name(&host, 0).await {
                Ok(addrs) => Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs),
                Err(e) => Err(Box::new(e) as Box<dyn StdError + Send + Sync>),
            }
        })
    }
}

/// Lower-case and strip one trailing dot, so `METADATA.google.internal.`
/// cannot slip past a suffix comparison.
fn normalize_name(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// True for names that RFC 6761 reserves for loopback.
fn is_localhost_name(name: &str) -> bool {
    let name = normalize_name(name);
    name == "localhost" || name.ends_with(".localhost")
}

/// True for loopback in any spelling: `127.0.0.0/8`, `::1`, or an
/// IPv4-mapped/compatible embedding of `127.0.0.0/8`.
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

/// True for any address an untrusted URL must never reach.
///
/// Includes loopback. See [`is_internal_v4`] and [`is_internal_v6`] for the
/// exact ranges.
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(&v4),
        IpAddr::V6(v6) => is_internal_v6(&v6),
    }
}

/// True for IPv4 addresses in a non-public range, per the IANA IPv4
/// Special-Purpose Address Registry plus ranges clouds route internally.
///
/// | Range | Purpose |
/// |---|---|
/// | `0.0.0.0/8` | "this network" (many stacks route `0.x` to the local host) |
/// | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 private |
/// | `100.64.0.0/10` | RFC 6598 CGNAT (routed to infrastructure in many VPCs) |
/// | `127.0.0.0/8` | loopback |
/// | `169.254.0.0/16` | link-local, incl. the cloud metadata service |
/// | `192.0.0.0/24` | IETF protocol assignments |
/// | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | documentation |
/// | `192.88.99.0/24` | deprecated 6to4 relay anycast |
/// | `198.18.0.0/15` | benchmarking (routed internally in some clouds) |
/// | `224.0.0.0/4` | multicast |
/// | `240.0.0.0/4` | reserved, incl. `255.255.255.255` broadcast |
pub fn is_internal_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    let this_network = o[0] == 0;
    let cgnat = o[0] == 100 && (64..128).contains(&o[1]);
    let protocol_assignments = o[0] == 192 && o[1] == 0 && o[2] == 0;
    let documentation = (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113);
    let relay_6to4 = o[0] == 192 && o[1] == 88 && o[2] == 99;
    let benchmarking = o[0] == 198 && (o[1] == 18 || o[1] == 19);
    let reserved = o[0] >= 240;

    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || this_network
        || cgnat
        || protocol_assignments
        || documentation
        || relay_6to4
        || benchmarking
        || reserved
}

/// True for IPv6 addresses in a non-public range, per the IANA IPv6
/// Special-Purpose Address Registry.
///
/// Every form that embeds an IPv4 address is unwrapped and judged by
/// [`is_internal_v4`], because the connector (or a NAT64 gateway / 6to4 relay
/// / Teredo tunnel) will deliver it to that IPv4 address:
///
/// - IPv4-mapped `::ffff:a.b.c.d` and IPv4-compatible `::a.b.c.d`
/// - IPv4-translated `::ffff:0:a.b.c.d` (RFC 2765)
/// - NAT64 well-known prefix `64:ff9b::/96` (on an IPv6-only cluster behind
///   DNS64/NAT64 — the standard IPv6 EKS/GKE setup — `[64:ff9b::a9fe:a9fe]`
///   *is* the metadata service)
/// - 6to4 `2002::/16` (v4 in segments 1–2)
/// - Teredo `2001::/32` (client v4 stored as the complement of the low 32 bits)
///
/// Native ranges refused outright: `::/128`, `::1/128`, `64:ff9b:1::/48`
/// (local-use NAT64), `100::/64` (discard), `2001:2::/48` (benchmarking),
/// `2001:db8::/32` and `3fff::/20` (documentation), `5f00::/16` (SRv6 SIDs),
/// `fc00::/7` (unique-local), `fe80::/10` (link-local), `fec0::/10`
/// (deprecated site-local), `ff00::/8` (multicast).
pub fn is_internal_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }

    // IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`).
    if let Some(v4) = ip.to_ipv4() {
        return is_internal_v4(&v4);
    }

    let s = ip.segments();
    let low_v4 = Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32);

    // IPv4-translated `::ffff:0:a.b.c.d` (RFC 2765), which `to_ipv4()` misses.
    if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
        return is_internal_v4(&low_v4);
    }

    // NAT64 well-known prefix 64:ff9b::/96 — the embedded v4 is the low 32
    // bits.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return is_internal_v4(&low_v4);
    }
    // Local-use NAT64 64:ff9b:1::/48 (RFC 8215): translator-specific, by
    // definition not public.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 {
        return true;
    }

    // 6to4 2002::/16 — the embedded v4 is segments 1 and 2.
    if s[0] == 0x2002 {
        let v4 = Ipv4Addr::from(((s[1] as u32) << 16) | s[2] as u32);
        return is_internal_v4(&v4);
    }

    // Teredo 2001::/32 — client v4 is the complement of the low 32 bits.
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return is_internal_v4(&Ipv4Addr::from(!u32::from(low_v4)));
    }

    let discard = s[0] == 0x0100 && s[1..4] == [0, 0, 0];
    let benchmarking = s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0;
    let documentation = (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] & 0xfff0) == 0x3ff0;
    let srv6 = s[0] == 0x5f00;
    let unique_local = (s[0] & 0xfe00) == 0xfc00;
    let link_local = (s[0] & 0xffc0) == 0xfe80;
    let site_local = (s[0] & 0xffc0) == 0xfec0;
    let multicast = (s[0] & 0xff00) == 0xff00;

    discard
        || benchmarking
        || documentation
        || srv6
        || unique_local
        || link_local
        || site_local
        || multicast
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Mutex;

    fn v4(s: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(s).unwrap()
    }

    fn v6(s: &str) -> Ipv6Addr {
        Ipv6Addr::from_str(s).unwrap()
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[derive(Default)]
    struct FakeResolver(Mutex<HashMap<String, Vec<IpAddr>>>);

    impl FakeResolver {
        fn with(host: &str, ips: &[&str]) -> Arc<Self> {
            let r = Self::default();
            r.0.lock().unwrap().insert(
                host.to_string(),
                ips.iter().map(|s| IpAddr::from_str(s).unwrap()).collect(),
            );
            Arc::new(r)
        }
    }

    #[async_trait]
    impl HostResolver for FakeResolver {
        async fn lookup(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.0
                .lock()
                .unwrap()
                .get(host)
                .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no record"))
        }
    }

    #[test]
    fn v4_special_purpose_ranges_are_internal() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(is_internal_v4(&v4(ip)), "{ip} must be internal");
        }
    }

    #[test]
    fn v4_public_and_boundaries_are_not_internal() {
        for ip in [
            "1.0.0.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
            "172.32.0.1",
            "192.0.1.1",
            "192.88.98.1",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            assert!(!is_internal_v4(&v4(ip)), "{ip} must be public");
        }
    }

    #[test]
    fn v6_embedded_v4_forms_are_unwrapped() {
        for ip in [
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
            "::169.254.169.254",
            "::ffff:0:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::10.0.0.1",
            "2002:a9fe:a9fe::",
            "2002:7f00:0001::",
            "2001:0:4136:e378:8000:63bf:5601:5601",
            "2001:0::80ff:fffe",
        ] {
            assert!(is_internal_v6(&v6(ip)), "{ip} must be internal");
        }
        for ip in [
            "::ffff:93.184.216.34",
            "::ffff:0:93.184.216.34",
            "64:ff9b::93.184.216.34",
            "2002:5db8:d822::",
            "2001:0:4136:e378:8000:63bf:a247:27dd",
        ] {
            assert!(!is_internal_v6(&v6(ip)), "{ip} must be public");
        }
    }

    #[test]
    fn v6_native_special_ranges_are_internal() {
        for ip in [
            "::",
            "::1",
            "64:ff9b:1::1",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(is_internal_v6(&v6(ip)), "{ip} must be internal");
        }
        assert!(!is_internal_v6(&v6("2606:2800:220:1:248:1893:25c8:1946")));
        assert!(!is_internal_v6(&v6("2a00:1450:4001::1")));
    }

    #[test]
    fn check_url_requires_https_by_default() {
        let p = EgressPolicy::default();
        assert_eq!(p.check_url(&url("https://example.com/")), Ok(()));
        assert_eq!(
            p.check_url(&url("http://example.com/")),
            Err(EgressError::SchemeNotAllowed)
        );
        assert_eq!(
            p.check_url(&url("ftp://example.com/")),
            Err(EgressError::SchemeNotAllowed)
        );
        assert_eq!(
            p.allow_http(true).check_url(&url("http://example.com/")),
            Ok(())
        );
    }

    #[test]
    fn check_url_refuses_internal_literals_and_names() {
        let p = EgressPolicy::default();
        for u in [
            "https://169.254.169.254/latest/meta-data/",
            "https://[::ffff:169.254.169.254]/",
            "https://10.0.0.1/",
            "https://127.0.0.1/",
            "https://0x7f.1/",
            "https://2130706433/",
            "https://[::1]/",
            "http://127.0.0.1:6379/",
            "https://localhost/",
            "https://foo.localhost/",
        ] {
            assert_eq!(
                p.check_url(&url(u)),
                Err(EgressError::InternalAddress),
                "{u}"
            );
        }
        for u in [
            "https://metadata.google.internal/",
            "https://METADATA.GOOGLE.INTERNAL./",
            "https://printer.local/",
            "https://router.home.arpa/",
        ] {
            assert_eq!(
                p.check_url(&url(u)),
                Err(EgressError::DeniedHostName),
                "{u}"
            );
        }
        assert_eq!(
            p.check_url(&url("data:text/plain,hi")),
            Err(EgressError::MissingHost)
        );
    }

    #[test]
    fn loopback_opt_in_relaxes_only_loopback() {
        let p = EgressPolicy::default().allow_insecure_loopback(true);
        assert_eq!(p.check_url(&url("http://127.0.0.1:8080/")), Ok(()));
        assert_eq!(p.check_url(&url("http://localhost:8080/")), Ok(()));
        assert_eq!(p.check_url(&url("http://[::1]:8080/")), Ok(()));
        assert_eq!(
            p.check_url(&url("https://169.254.169.254/")),
            Err(EgressError::InternalAddress)
        );
        assert_eq!(
            p.check_url(&url("http://example.com/")),
            Err(EgressError::SchemeNotAllowed)
        );
    }

    #[tokio::test]
    async fn resolve_refuses_name_pointing_at_internal_address() {
        let p = EgressPolicy::default().with_resolver(FakeResolver::with(
            "evil.example",
            &["93.184.216.34", "169.254.169.254"],
        ));
        assert_eq!(
            p.resolve(&url("https://evil.example/")).await,
            Err(EgressError::InternalAddress)
        );
    }

    #[tokio::test]
    async fn resolve_refuses_name_pointing_at_loopback() {
        let p = EgressPolicy::default()
            .with_resolver(FakeResolver::with("rebind.example", &["127.0.0.1"]));
        assert_eq!(
            p.resolve(&url("https://rebind.example/")).await,
            Err(EgressError::InternalAddress)
        );
    }

    #[tokio::test]
    async fn resolve_returns_vetted_public_answers() {
        let p = EgressPolicy::default()
            .with_resolver(FakeResolver::with("ok.example", &["93.184.216.34"]));
        let addrs = p.resolve(&url("https://ok.example:8443/")).await.unwrap();
        assert_eq!(addrs, vec!["93.184.216.34:8443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn resolve_maps_lookup_failure_and_timeout_to_unresolvable() {
        let p = EgressPolicy::default().with_resolver(Arc::new(FakeResolver::default()));
        assert_eq!(
            p.resolve(&url("https://nx.example/")).await,
            Err(EgressError::Unresolvable)
        );

        struct Hang;
        #[async_trait]
        impl HostResolver for Hang {
            async fn lookup(&self, _: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
                std::future::pending().await
            }
        }
        let p = EgressPolicy::default()
            .with_resolver(Arc::new(Hang))
            .resolve_timeout(Duration::from_millis(20));
        assert_eq!(
            p.resolve(&url("https://slow.example/")).await,
            Err(EgressError::Unresolvable)
        );
    }

    #[tokio::test]
    async fn guarded_resolver_blocks_reqwest_connection_and_is_findable() {
        let p = EgressPolicy::default()
            .with_resolver(FakeResolver::with("meta.example", &["169.254.169.254"]));
        let client = p.apply(reqwest::Client::builder()).build().unwrap();
        let err = client
            .get("https://meta.example/latest/meta-data/")
            .send()
            .await
            .unwrap_err();
        assert_eq!(
            EgressError::find_in(&err),
            Some(&EgressError::InternalAddress)
        );
    }
}
