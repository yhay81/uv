use std::sync::Arc;

use thiserror::Error;
use uv_auth::RealmRef;
use uv_cache_key::CanonicalUrl;
use uv_normalize::PackageName;
use uv_pep508::VerbatimUrl;
use uv_redacted::{DisplaySafeUrl, DisplaySafeUrlError};

use crate::{Index, IndexFormat, IndexLocations, IndexName, IndexUrl, PYPI_URL, ToUrlError};

const PYPI_ARTIFACT_BASE_URL: &str = "https://files.pythonhosted.org/packages/";

/// An invalid proxy index or artifact URL.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProxyIndexError {
    /// The proxy does not identify a configured canonical Simple API index.
    #[error("The proxy index does not reference a configured package index")]
    MissingCanonicalIndex,

    /// More than one proxy references the same canonical package index.
    #[error("More than one proxy index references the package index `{index}`")]
    DuplicateCanonicalIndex {
        /// The canonical package index with multiple proxy declarations.
        index: Box<DisplaySafeUrl>,
    },

    /// A physical proxy must explicitly identify where its artifacts are hosted.
    #[error("Proxy index `{index}` requires an `artifact-base-url`")]
    MissingProxyArtifactBase {
        /// The physical proxy index without a configured artifact base.
        index: Box<DisplaySafeUrl>,
    },

    /// A non-PyPI canonical index must explicitly identify its artifact host.
    #[error("Canonical index `{index}` requires an `artifact-base-url`")]
    MissingCanonicalArtifactBase {
        /// The canonical package index without a configured artifact base.
        index: Box<DisplaySafeUrl>,
    },

    /// A selected proxied artifact has no supported advertised integrity digest.
    #[error(
        "Cannot lock `{filename}` for `{package}` from proxy index `{physical}` because it has no supported advertised digest"
    )]
    MissingDigest {
        /// The package containing the selected artifact.
        package: PackageName,
        /// The selected wheel or source distribution filename.
        filename: String,
        /// The credential-redacted physical proxy endpoint.
        physical: Box<DisplaySafeUrl>,
    },

    /// An index or artifact base is not a safe absolute HTTP(S) URL prefix.
    #[error("Invalid proxy URL mapping `{url}`: {reason}")]
    InvalidMapping {
        /// The invalid canonical or physical URL.
        url: Box<DisplaySafeUrl>,
        /// The reason the URL cannot safely be used as a reversible prefix.
        reason: &'static str,
    },

    /// A proxied artifact URL does not match the configured artifact base.
    #[error("No proxy artifact URL mapping matches `{url}`")]
    UnmappedUrl {
        /// The unmatched canonical or physical artifact URL.
        url: Box<DisplaySafeUrl>,
    },

    /// A registry artifact location could not be converted to an absolute URL.
    #[error(transparent)]
    InvalidArtifactUrl(#[from] ToUrlError),

    /// An artifact base or rewritten URL was invalid.
    #[error(transparent)]
    InvalidUrl(#[from] DisplaySafeUrlError),
}

/// The paired artifact bases of a canonical index and its physical proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactUrlMapping {
    canonical: DisplaySafeUrl,
    physical: DisplaySafeUrl,
}

/// A validated canonical-to-physical route for a package index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRoute {
    /// The index identity used by the resolver and lockfile.
    pub canonical: IndexUrl,
    /// The physical index used for requests, authentication, and caches.
    pub physical: IndexUrl,
    artifact_mapping: Option<Arc<ArtifactUrlMapping>>,
}

impl IndexRoute {
    /// Return whether this index is routed through a configured proxy.
    pub fn is_proxy(&self) -> bool {
        self.artifact_mapping.is_some()
    }

    /// Translate a canonical artifact URL to its configured physical proxy URL.
    pub fn to_proxy_url(&self, url: &DisplaySafeUrl) -> Result<DisplaySafeUrl, ProxyIndexError> {
        self.rewrite_artifact_url(url, MappingDirection::ToProxy)
    }

    /// Translate a physical proxy artifact URL to its configured canonical URL.
    pub fn to_canonical_url(
        &self,
        url: &DisplaySafeUrl,
    ) -> Result<DisplaySafeUrl, ProxyIndexError> {
        self.rewrite_artifact_url(url, MappingDirection::ToCanonical)
    }

    fn rewrite_artifact_url(
        &self,
        url: &DisplaySafeUrl,
        direction: MappingDirection,
    ) -> Result<DisplaySafeUrl, ProxyIndexError> {
        let Some(mapping) = &self.artifact_mapping else {
            return Ok(url.clone());
        };

        let (prefix, target) = match direction {
            MappingDirection::ToProxy => (&mapping.canonical, &mapping.physical),
            MappingDirection::ToCanonical => (&mapping.physical, &mapping.canonical),
        };
        let Some(suffix) = path_suffix(url, prefix) else {
            return Err(ProxyIndexError::UnmappedUrl {
                url: Box::new(url.clone()),
            });
        };

        let mut rewritten = target.clone();
        let target_path = target.path().trim_end_matches('/');
        if suffix.is_empty() {
            if prefix.path().ends_with('/') && !target.path().ends_with('/') {
                rewritten.set_path(&format!("{target_path}/"));
            }
        } else {
            rewritten.set_path(&format!("{target_path}/{suffix}"));
        }
        rewritten.set_query(url.query());
        rewritten.set_fragment(url.fragment());
        Ok(rewritten)
    }
}

#[derive(Debug, Clone, Copy)]
enum MappingDirection {
    ToProxy,
    ToCanonical,
}

/// Validated proxy routes derived from ordinary configured package indexes.
#[derive(Debug, Default, Clone)]
pub struct IndexRoutes {
    routes: Vec<IndexRoute>,
}

impl IndexRoutes {
    /// Return the physical route for an index, or its unchanged direct route.
    pub fn route_for(&self, index: &IndexUrl) -> IndexRoute {
        if let Some(route) = self
            .routes
            .iter()
            .find(|route| same_index(&route.canonical, index))
        {
            return IndexRoute {
                canonical: index.clone(),
                physical: route.physical.clone(),
                artifact_mapping: route.artifact_mapping.clone(),
            };
        }

        IndexRoute {
            canonical: index.clone(),
            physical: index.clone(),
            artifact_mapping: None,
        }
    }

    /// Iterate over the configured canonical-to-physical proxy routes.
    pub fn proxy_routes(&self) -> impl Iterator<Item = &IndexRoute> {
        self.routes.iter()
    }
}

impl TryFrom<&IndexLocations> for IndexRoutes {
    type Error = ProxyIndexError;

    fn try_from(locations: &IndexLocations) -> Result<Self, Self::Error> {
        let mut routes = Vec::new();

        for proxy in locations.proxy_indexes() {
            let Some(canonical_name) = &proxy.proxy_for else {
                continue;
            };

            if proxy.format != IndexFormat::Simple {
                return Err(ProxyIndexError::InvalidMapping {
                    url: Box::new(proxy.url.url().clone()),
                    reason: "proxy indexes must use the Simple API format",
                });
            }

            let canonical = find_canonical_index(locations, canonical_name)
                .ok_or(ProxyIndexError::MissingCanonicalIndex)?;

            if routes
                .iter()
                .any(|route: &IndexRoute| same_index(&route.canonical, canonical.url()))
            {
                return Err(ProxyIndexError::DuplicateCanonicalIndex {
                    index: Box::new(canonical.url.url().clone()),
                });
            }

            let canonical_url = canonical.url.url();
            let physical_url = proxy.url.url();
            validate_prefix(canonical_url)?;
            validate_prefix(physical_url)?;

            let canonical_artifact_base = artifact_base(canonical)?;
            let physical_artifact_base = proxy.artifact_base_url.clone().ok_or_else(|| {
                ProxyIndexError::MissingProxyArtifactBase {
                    index: Box::new(physical_url.clone()),
                }
            })?;
            validate_prefix(&canonical_artifact_base)?;
            validate_prefix(&physical_artifact_base)?;
            validate_canonical_prefix(&canonical_artifact_base)?;

            routes.push(IndexRoute {
                canonical: canonical.url.clone(),
                physical: proxy.url.clone(),
                artifact_mapping: Some(Arc::new(ArtifactUrlMapping {
                    canonical: canonical_artifact_base,
                    physical: physical_artifact_base,
                })),
            });
        }

        Ok(Self { routes })
    }
}

fn find_canonical_index<'a>(locations: &'a IndexLocations, name: &IndexName) -> Option<&'a Index> {
    locations
        .configured_indexes()
        .find(|index| {
            index.format == IndexFormat::Simple
                && index.proxy_for.is_none()
                && index.name.as_ref() == Some(name)
        })
        .or_else(|| {
            if name.as_ref() != "pypi" {
                return None;
            }

            let pypi = IndexUrl::from(VerbatimUrl::from_url(PYPI_URL.clone()));
            locations
                .default_index()
                .filter(|index| index.proxy_for.is_none() && same_index(index.url(), &pypi))
        })
}

fn artifact_base(index: &Index) -> Result<DisplaySafeUrl, ProxyIndexError> {
    if let Some(base) = &index.artifact_base_url {
        return Ok(base.clone());
    }

    let pypi = IndexUrl::from(VerbatimUrl::from_url(PYPI_URL.clone()));
    if same_index(index.url(), &pypi) {
        return Ok(DisplaySafeUrl::parse(PYPI_ARTIFACT_BASE_URL)?);
    }

    Err(ProxyIndexError::MissingCanonicalArtifactBase {
        index: Box::new(index.url.url().clone()),
    })
}

fn same_index(first: &IndexUrl, second: &IndexUrl) -> bool {
    RealmRef::from(&**first.url()) == RealmRef::from(&**second.url())
        && CanonicalUrl::new(first.url().clone()) == CanonicalUrl::new(second.url().clone())
}

fn same_origin(first: &DisplaySafeUrl, second: &DisplaySafeUrl) -> bool {
    first.scheme() == second.scheme()
        && first.host_str() == second.host_str()
        && first.port_or_known_default() == second.port_or_known_default()
}

fn path_suffix<'a>(url: &'a DisplaySafeUrl, prefix: &DisplaySafeUrl) -> Option<&'a str> {
    if !same_origin(url, prefix) {
        return None;
    }

    let prefix_path = prefix.path().trim_end_matches('/');
    let candidate_path = url.path();
    if candidate_path == prefix_path {
        return Some("");
    }

    candidate_path
        .strip_prefix(prefix_path)
        .and_then(|suffix| suffix.strip_prefix('/'))
}

fn validate_canonical_prefix(url: &DisplaySafeUrl) -> Result<(), ProxyIndexError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ProxyIndexError::InvalidMapping {
            url: Box::new(url.clone()),
            reason: "canonical URL prefixes cannot contain credentials",
        });
    }

    Ok(())
}

fn validate_prefix(url: &DisplaySafeUrl) -> Result<(), ProxyIndexError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ProxyIndexError::InvalidMapping {
            url: Box::new(url.clone()),
            reason: "index and artifact base URLs must use HTTP or HTTPS",
        });
    }

    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProxyIndexError::InvalidMapping {
            url: Box::new(url.clone()),
            reason: "index and artifact base URLs cannot contain queries or fragments",
        });
    }

    for segment in url.path().split('/') {
        let Ok(decoded) = percent_encoding::percent_decode_str(segment).decode_utf8() else {
            return Err(ProxyIndexError::InvalidMapping {
                url: Box::new(url.clone()),
                reason: "index and artifact base URLs must contain valid UTF-8 path segments",
            });
        };

        if matches!(decoded.as_ref(), "." | "..")
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded.contains('\0')
        {
            return Err(ProxyIndexError::InvalidMapping {
                url: Box::new(url.clone()),
                reason: "index and artifact base URLs cannot contain path traversal or encoded separators",
            });
        }
    }

    Ok(())
}

pub(crate) fn validate_raw_prefix(value: &str) -> Result<(), &'static str> {
    let Some((_, authority_and_path)) = value.split_once("://") else {
        return Ok(());
    };
    let Some((_, path)) = authority_and_path.split_once('/') else {
        return Ok(());
    };
    let path = path.split_once(['?', '#']).map_or(path, |(path, _)| path);

    for segment in path.split('/') {
        let decoded = percent_encoding::percent_decode_str(segment)
            .decode_utf8()
            .map_err(|_| "artifact base URLs must contain valid UTF-8 path segments")?;

        if matches!(decoded.as_ref(), "." | "..")
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded.contains('\0')
        {
            return Err("artifact base URLs cannot contain path traversal or encoded separators");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn url(value: &str) -> Result<DisplaySafeUrl, Box<dyn std::error::Error>> {
        Ok(DisplaySafeUrl::parse(value)?)
    }

    fn index_url(value: &str) -> Result<IndexUrl, Box<dyn std::error::Error>> {
        Ok(IndexUrl::from(VerbatimUrl::from_url(url(value)?)))
    }

    fn named_index(
        name: &str,
        index: &str,
        artifact: Option<&str>,
        proxy_for: Option<&str>,
    ) -> Result<Index, Box<dyn std::error::Error>> {
        let mut index = Index::from_extra_index_url(index_url(index)?);
        index.name = Some(name.parse()?);
        index.artifact_base_url = artifact.map(url).transpose()?;
        index.proxy_for = proxy_for.map(str::parse).transpose()?;
        Ok(index)
    }

    fn pypi_proxy() -> Result<Index, Box<dyn std::error::Error>> {
        named_index(
            "socket",
            "https://proxy.example.com/simple/",
            Some("https://proxy.example.com/files/"),
            Some("pypi"),
        )
    }

    fn pypi_locations(proxy: Index) -> IndexLocations {
        IndexLocations::new(vec![proxy], Vec::new(), false)
    }

    #[test]
    fn proxy_simple_route_maps_implicit_pypi() -> TestResult {
        let routes = IndexRoutes::try_from(&pypi_locations(pypi_proxy()?))?;
        let canonical = index_url("https://pypi.org/simple")?;
        let route = routes.route_for(&canonical);

        assert!(route.is_proxy());
        assert_eq!(route.canonical, canonical);
        assert_eq!(
            route.physical,
            index_url("https://proxy.example.com/simple/")?
        );
        assert_eq!(routes.proxy_routes().count(), 1);
        Ok(())
    }

    #[test]
    fn proxy_flat_index_keeps_identity_route() -> TestResult {
        let flat = index_url("https://flat.example.com/packages/")?;
        let locations = IndexLocations::new(
            vec![pypi_proxy()?],
            vec![Index::from_find_links(flat.clone())],
            false,
        );
        let routes = IndexRoutes::try_from(&locations)?;
        let route = routes.route_for(&flat);

        assert!(!route.is_proxy());
        assert_eq!(route.canonical, flat);
        assert_eq!(route.physical, flat);
        let artifact = url("https://flat.example.com/packages/package.whl?download=1#sha256=abc")?;
        assert_eq!(route.to_proxy_url(&artifact)?, artifact);
        assert_eq!(route.to_canonical_url(&artifact)?, artifact);
        Ok(())
    }

    #[test]
    fn proxy_artifact_mapping_preserves_encoded_suffix_and_query() -> TestResult {
        let routes = IndexRoutes::try_from(&pypi_locations(pypi_proxy()?))?;
        let route = routes.route_for(&index_url("https://pypi.org/simple/")?);
        let canonical = url(
            "https://files.pythonhosted.org/packages/example%20project/package%2B1.whl?download=1#sha256=abc",
        )?;
        let expected = url(
            "https://proxy.example.com/files/example%20project/package%2B1.whl?download=1#sha256=abc",
        )?;

        let physical = route.to_proxy_url(&canonical)?;
        assert_eq!(physical, expected);
        assert_eq!(route.to_canonical_url(&physical)?, canonical);
        Ok(())
    }

    #[test]
    fn proxy_artifact_mapping_requires_a_segment_boundary() -> TestResult {
        let routes = IndexRoutes::try_from(&pypi_locations(pypi_proxy()?))?;
        let route = routes.route_for(&index_url("https://pypi.org/simple/")?);
        for artifact in [
            "https://files.pythonhosted.org/packages-extra/package.whl",
            "https://unmapped.example.com/files/package.whl",
        ] {
            assert!(matches!(
                route.to_proxy_url(&url(artifact)?),
                Err(ProxyIndexError::UnmappedUrl { .. })
            ));
        }
        assert!(matches!(
            route.to_canonical_url(&url("https://proxy.example.com/unknown/package.whl")?),
            Err(ProxyIndexError::UnmappedUrl { .. })
        ));
        Ok(())
    }

    #[test]
    fn proxy_custom_index_uses_both_configured_artifact_bases() -> TestResult {
        let canonical = named_index(
            "upstream",
            "https://canonical-user:canonical-secret@upstream.example.com/simple/",
            Some("https://artifacts.example.com/distributions/"),
            None,
        )?;
        let proxy = named_index(
            "mirror",
            "https://proxy.example.com/simple/",
            Some("https://proxy.example.com/files/"),
            Some("upstream"),
        )?;
        let locations = IndexLocations::new(vec![canonical.clone(), proxy], Vec::new(), false);
        let routes = IndexRoutes::try_from(&locations)?;
        let route = routes.route_for(canonical.url());
        let canonical_artifact = url("https://artifacts.example.com/distributions/package.whl")?;

        assert_eq!(route.canonical.url().username(), "canonical-user");
        assert_eq!(route.canonical.url().password(), Some("canonical-secret"));
        assert_eq!(
            route.to_proxy_url(&canonical_artifact)?,
            url("https://proxy.example.com/files/package.whl")?
        );
        assert_eq!(
            route.to_canonical_url(&url("https://proxy.example.com/files/package.whl")?)?,
            canonical_artifact,
        );
        Ok(())
    }

    #[test]
    fn proxy_index_rejects_missing_artifact_bases_and_duplicate_targets() -> TestResult {
        let missing_physical = named_index(
            "socket",
            "https://proxy.example.com/simple/",
            None,
            Some("pypi"),
        )?;

        assert!(matches!(
            IndexRoutes::try_from(&pypi_locations(missing_physical)),
            Err(ProxyIndexError::MissingProxyArtifactBase { .. })
        ));

        let canonical = named_index(
            "upstream",
            "https://upstream.example.com/simple/",
            None,
            None,
        )?;
        let proxy = named_index(
            "mirror",
            "https://proxy.example.com/simple/",
            Some("https://proxy.example.com/files/"),
            Some("upstream"),
        )?;
        let locations = IndexLocations::new(vec![canonical.clone(), proxy], Vec::new(), false);

        assert!(matches!(
            IndexRoutes::try_from(&locations),
            Err(ProxyIndexError::MissingCanonicalArtifactBase { .. })
        ));

        let first = pypi_proxy()?;
        let second = named_index(
            "other-proxy",
            "https://other-proxy.example.com/simple/",
            Some("https://other-proxy.example.com/files/"),
            Some("pypi"),
        )?;
        let locations = IndexLocations::new(vec![first, second], Vec::new(), false);

        assert!(matches!(
            IndexRoutes::try_from(&locations),
            Err(ProxyIndexError::DuplicateCanonicalIndex { .. })
        ));

        Ok(())
    }

    #[test]
    fn proxy_index_uses_the_first_same_named_configuration() -> TestResult {
        let first = pypi_proxy()?;
        let shadowed = named_index(
            "socket",
            "https://user:secret@shadowed.example.com/simple/",
            Some("https://artifact-user:artifact-secret@shadowed.example.com/files/"),
            Some("pypi"),
        )?;
        let locations = IndexLocations::new(vec![first, shadowed], Vec::new(), false);
        let routes = IndexRoutes::try_from(&locations)?;
        let route = routes.route_for(&index_url("https://pypi.org/simple/")?);
        let artifact =
            route.to_proxy_url(&url("https://files.pythonhosted.org/packages/package.whl")?)?;

        assert_eq!(routes.proxy_routes().count(), 1);
        assert_eq!(
            route.physical,
            index_url("https://proxy.example.com/simple/")?
        );
        assert!(route.physical.url().username().is_empty());
        assert!(route.physical.url().password().is_none());
        assert!(artifact.username().is_empty());
        assert!(artifact.password().is_none());
        let ordinary = named_index("socket", "https://ordinary.example.com/simple/", None, None)?;
        for (indexes, expected_proxy) in [
            (vec![ordinary.clone(), pypi_proxy()?], false),
            (vec![pypi_proxy()?, ordinary], true),
        ] {
            let routes = IndexRoutes::try_from(&IndexLocations::new(indexes, Vec::new(), false))?;
            assert_eq!(routes.proxy_routes().count(), usize::from(expected_proxy));
            assert_eq!(
                routes
                    .route_for(&index_url("https://pypi.org/simple/")?)
                    .is_proxy(),
                expected_proxy,
            );
        }

        Ok(())
    }

    #[test]
    fn proxy_index_requires_a_configured_canonical_index() -> TestResult {
        let unknown_proxy = named_index(
            "mirror",
            "https://proxy.example.com/simple/",
            Some("https://proxy.example.com/files/"),
            Some("missing"),
        )?;
        let chained_proxy = named_index(
            "other-proxy",
            "https://other-proxy.example.com/simple/",
            Some("https://other-proxy.example.com/files/"),
            Some("socket"),
        )?;
        let mut flat =
            Index::from_find_links(index_url("https://canonical.example.com/packages/")?);
        flat.name = Some("flat".parse()?);
        let flat_proxy = named_index(
            "mirror",
            "https://proxy.example.com/simple/",
            Some("https://proxy.example.com/files/"),
            Some("flat"),
        )?;

        for locations in [
            pypi_locations(unknown_proxy),
            IndexLocations::new(vec![pypi_proxy()?, chained_proxy], Vec::new(), false),
            IndexLocations::new(vec![flat_proxy], vec![flat], false),
        ] {
            assert!(matches!(
                IndexRoutes::try_from(&locations),
                Err(ProxyIndexError::MissingCanonicalIndex)
            ));
        }

        Ok(())
    }

    #[test]
    fn proxy_index_rejects_canonical_artifact_credentials() -> TestResult {
        let canonical = named_index(
            "private",
            "https://canonical.example.com/simple/",
            Some("https://user:secret@canonical.example.com/files/"),
            None,
        )?;
        let proxy = named_index(
            "mirror",
            "https://proxy.example.com/simple/",
            Some("https://proxy.example.com/files/"),
            Some("private"),
        )?;
        let locations = IndexLocations::new(vec![canonical, proxy], Vec::new(), false);

        let Err(error) = IndexRoutes::try_from(&locations) else {
            return Err("canonical artifact credentials were unexpectedly accepted".into());
        };
        assert!(matches!(error, ProxyIndexError::InvalidMapping { .. }));
        assert!(!error.to_string().contains("secret"));
        Ok(())
    }

    #[test]
    fn proxy_index_preserves_physical_authentication_credentials() -> TestResult {
        let proxy = named_index(
            "socket",
            "https://user:secret@proxy.example.com/simple/",
            Some("https://artifact-user:artifact-secret@proxy.example.com/files/"),
            Some("pypi"),
        )?;
        let routes = IndexRoutes::try_from(&pypi_locations(proxy))?;
        let route = routes.route_for(&index_url("https://pypi.org/simple/")?);
        let canonical_artifact = url("https://files.pythonhosted.org/packages/package.whl")?;
        let physical_artifact = route.to_proxy_url(&canonical_artifact)?;

        assert_eq!(route.physical.url().username(), "user");
        assert_eq!(route.physical.url().password(), Some("secret"));
        assert_eq!(physical_artifact.username(), "artifact-user");
        assert_eq!(physical_artifact.password(), Some("artifact-secret"));
        Ok(())
    }

    #[test]
    fn proxy_index_rejects_unsafe_index_and_artifact_bases() -> TestResult {
        for physical in [
            "ftp://proxy.example.com/simple/",
            "file:///proxy/simple/",
            "https://proxy.example.com/simple/?download=1",
            "https://proxy.example.com/simple/#fragment",
            "https://proxy.example.com/simple%2fprivate/",
            "https://proxy.example.com/simple%5cprivate/",
        ] {
            let proxy = named_index("socket", physical, None, Some("pypi"))?;

            assert!(
                matches!(
                    IndexRoutes::try_from(&pypi_locations(proxy)),
                    Err(ProxyIndexError::InvalidMapping { .. })
                ),
                "unsafe proxy URL was accepted: {physical}"
            );
        }

        for artifact in [
            "ftp://proxy.example.com/files/",
            "https://proxy.example.com/files/?download=1",
            "https://proxy.example.com/files/#fragment",
            "https://proxy.example.com/files%2fprivate/",
            "https://proxy.example.com/files%5cprivate/",
        ] {
            let proxy = named_index(
                "socket",
                "https://proxy.example.com/simple/",
                Some(artifact),
                Some("pypi"),
            )?;

            assert!(
                matches!(
                    IndexRoutes::try_from(&pypi_locations(proxy)),
                    Err(ProxyIndexError::InvalidMapping { .. })
                ),
                "unsafe proxy artifact base was accepted: {artifact}"
            );
        }

        let mut proxy = pypi_proxy()?;
        proxy.format = IndexFormat::Flat;
        assert!(matches!(
            IndexRoutes::try_from(&pypi_locations(proxy)),
            Err(ProxyIndexError::InvalidMapping { .. })
        ));

        Ok(())
    }

    #[test]
    fn proxy_index_ignores_proxies_when_indexes_are_disabled() -> TestResult {
        let canonical = named_index(
            "upstream",
            "https://upstream.example.com/simple/",
            Some("https://upstream.example.com/files/"),
            None,
        )?;
        let proxy = named_index(
            "mirror",
            "https://proxy.example.com/simple/",
            Some("https://proxy.example.com/files/"),
            Some("upstream"),
        )?;

        for (locations, expected_canonical) in [
            (
                IndexLocations::new(vec![pypi_proxy()?], Vec::new(), true),
                index_url("https://pypi.org/simple/")?,
            ),
            (
                IndexLocations::new(vec![canonical.clone(), proxy], Vec::new(), true),
                canonical.url().clone(),
            ),
        ] {
            let routes = IndexRoutes::try_from(&locations)?;
            assert_eq!(routes.proxy_routes().count(), 0);
            assert!(!routes.route_for(&expected_canonical).is_proxy());
        }

        Ok(())
    }

    #[test]
    fn raw_artifact_base_rejects_traversal_and_encoded_separators() {
        for path in [
            "../files/",
            "./files/",
            "%2e%2e/files/",
            "%2e/files/",
            "files%2fprivate/",
            "files%2Fprivate/",
            "files%5cprivate/",
            "files%5Cprivate/",
        ] {
            let value = format!("https://proxy.example.com/{path}");
            assert!(validate_raw_prefix(&value).is_err());
        }
    }
}
