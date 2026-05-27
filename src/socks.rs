use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cli::Auth;
use crate::connector::{BoxStream, Connector, Target, relay};

pub async fn serve(
    mut client: BoxStream,
    first_byte: Option<u8>,
    connector: Arc<Connector>,
    auth: Option<&Auth>,
) -> Result<()> {
    let version = match first_byte {
        Some(byte) => byte,
        None => read_u8(&mut client).await?,
    };
    if version != 0x05 {
        bail!("unsupported SOCKS version")
    }
    authenticate(&mut client, auth).await?;
    let target = read_request(&mut client).await?;
    let remote = match connector.connect(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            write_reply(&mut client, 0x04).await?;
            return Err(error);
        }
    };
    write_reply(&mut client, 0x00).await?;
    relay(client, remote).await?;
    Ok(())
}

async fn authenticate(client: &mut BoxStream, auth: Option<&Auth>) -> Result<()> {
    let method_count = read_u8(client).await? as usize;
    let mut methods = vec![0_u8; method_count];
    client.read_exact(&mut methods).await?;
    let selected = if auth.is_some() { 0x02 } else { 0x00 };
    if !methods.contains(&selected) {
        client.write_all(&[0x05, 0xff]).await?;
        bail!("SOCKS5 client did not offer required authentication method")
    }
    client.write_all(&[0x05, selected]).await?;
    if let Some(auth) = auth {
        if read_u8(client).await? != 0x01 {
            bail!("invalid SOCKS5 username/password authentication version")
        }
        let username = read_string(client).await?;
        let password = read_string(client).await?;
        if username != auth.username || password != auth.password {
            client.write_all(&[0x01, 0x01]).await?;
            bail!("SOCKS5 authentication failed")
        }
        client.write_all(&[0x01, 0x00]).await?;
    }
    Ok(())
}

async fn read_request(client: &mut BoxStream) -> Result<Target> {
    let mut prefix = [0_u8; 3];
    client.read_exact(&mut prefix).await?;
    if prefix != [0x05, 0x01, 0x00] {
        write_reply(client, 0x07).await?;
        bail!("only SOCKS5 CONNECT is supported")
    }
    let host = match read_u8(client).await? {
        0x01 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        0x03 => read_string(client).await?,
        0x04 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        _ => {
            write_reply(client, 0x08).await?;
            bail!("unsupported SOCKS5 target address type")
        }
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    Ok(Target::new(host, u16::from_be_bytes(port)))
}

async fn write_reply(client: &mut BoxStream, status: u8) -> Result<()> {
    client
        .write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn read_string(client: &mut BoxStream) -> Result<String> {
    let length = read_u8(client).await? as usize;
    let mut bytes = vec![0_u8; length];
    client.read_exact(&mut bytes).await?;
    Ok(String::from_utf8(bytes)?)
}

async fn read_u8(client: &mut BoxStream) -> Result<u8> {
    let mut byte = [0_u8; 1];
    client.read_exact(&mut byte).await?;
    Ok(byte[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connects_and_relays_socks5_traffic() {
        let origin = TcpListener::bind("127.0.0.1:0").await.expect("origin bind");
        let port = origin.local_addr().expect("origin address").port();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.expect("origin accept");
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await.expect("origin input");
            assert_eq!(input, b"hello");
            stream.write_all(b"world").await.expect("origin output");
        });
        let (mut caller, proxy_client) = tokio::io::duplex(4096);
        let connector = Arc::new(Connector::new(None, None).expect("connector"));
        let proxy_task =
            tokio::spawn(async move { serve(Box::new(proxy_client), None, connector, None).await });

        caller.write_all(&[0x05, 0x01, 0x00]).await.expect("hello");
        let mut method = [0_u8; 2];
        caller.read_exact(&mut method).await.expect("method");
        assert_eq!(method, [0x05, 0x00]);
        let mut connect = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        connect.extend_from_slice(&port.to_be_bytes());
        caller.write_all(&connect).await.expect("connect");
        let mut reply = [0_u8; 10];
        caller.read_exact(&mut reply).await.expect("reply");
        assert_eq!(reply[1], 0x00);
        caller.write_all(b"hello").await.expect("payload");
        caller.shutdown().await.expect("payload shutdown");
        let mut output = Vec::new();
        caller.read_to_end(&mut output).await.expect("response");

        origin_task.await.expect("origin task");
        proxy_task.await.expect("proxy task").expect("proxy result");
        assert_eq!(output, b"world");
    }
}
