//! Web-looking HTTP replies used to hide proxy fingerprints.
//!
//! nmap version detection classifies `407` and `502` replies as `http-proxy`.
//! Origin-form scanner probes such as `GET /` are answered with a generic nginx
//! 404 page so the listener looks like a normal HTTP server.

use anyhow::Result;
use tokio::io::AsyncWriteExt;

use crate::connector::BoxStream;

const NOT_FOUND_BODY: &str = "<html>\r\n\
<head><title>404 Not Found</title></head>\r\n\
<body>\r\n\
<center><h1>404 Not Found</h1></center>\r\n\
<hr><center>nginx</center>\r\n\
</body>\r\n\
</html>\r\n";

const SERVICE_UNAVAILABLE_BODY: &str = "<html>\r\n\
<head><title>503 Service Temporarily Unavailable</title></head>\r\n\
<body>\r\n\
<center><h1>503 Service Temporarily Unavailable</h1></center>\r\n\
<hr><center>nginx</center>\r\n\
</body>\r\n\
</html>\r\n";

/// Build a closed nginx-looking HTTP response.
///
/// # Parameters
///
/// * `status` - Status line without the trailing CRLF, such as `404 Not Found`.
/// * `body` - HTML body whose length is written as `Content-Length`.
///
/// # Returns
///
/// Returns a complete HTTP/1.1 response including headers and body.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let reply = camouflage_response("404 Not Found", NOT_FOUND_BODY);
/// ```
fn camouflage_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\n\
         Server: nginx\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
    .into_bytes()
}

/// Write a camouflage 404 response and close the HTTP conversation.
///
/// # Parameters
///
/// * `stream` - Client stream that received a non-proxy or invalid request.
///
/// # Returns
///
/// Returns `Ok(())` after the response is written.
///
/// # Errors
///
/// Returns an error when writing the response fails.
///
/// # Examples
///
/// ```ignore
/// camouflage::write_not_found(&mut client).await?;
/// ```
pub async fn write_not_found(stream: &mut BoxStream) -> Result<()> {
    stream
        .write_all(&camouflage_response("404 Not Found", NOT_FOUND_BODY))
        .await?;
    Ok(())
}

/// Write a camouflage 503 response used in place of `502 Bad Gateway`.
///
/// # Parameters
///
/// * `stream` - Client stream waiting for a proxy or tunnel error reply.
///
/// # Returns
///
/// Returns `Ok(())` after the response is written.
///
/// # Errors
///
/// Returns an error when writing the response fails.
///
/// # Examples
///
/// ```ignore
/// camouflage::write_service_unavailable(&mut client).await?;
/// ```
pub async fn write_service_unavailable(stream: &mut BoxStream) -> Result<()> {
    stream
        .write_all(&camouflage_response(
            "503 Service Temporarily Unavailable",
            SERVICE_UNAVAILABLE_BODY,
        ))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camouflage_responses_look_like_nginx() {
        let not_found = camouflage_response("404 Not Found", NOT_FOUND_BODY);
        let unavailable = camouflage_response(
            "503 Service Temporarily Unavailable",
            SERVICE_UNAVAILABLE_BODY,
        );
        let not_found = String::from_utf8(not_found).expect("UTF-8");
        let unavailable = String::from_utf8(unavailable).expect("UTF-8");

        assert!(not_found.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(not_found.contains("Server: nginx\r\n"));
        assert!(not_found.contains(&format!("Content-Length: {}\r\n", NOT_FOUND_BODY.len())));
        assert!(unavailable.starts_with("HTTP/1.1 503 Service Temporarily Unavailable\r\n"));
        assert!(!unavailable.contains("502"));
    }
}
