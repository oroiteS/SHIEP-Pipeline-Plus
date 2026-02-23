use crate::error::{EcError, EcResult};
use std::io::{Read, Write};
use std::net::{Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::thread;

pub fn serve(bind_addr: &str) -> EcResult<()> {
    let normalized = normalize_bind_addr(bind_addr);
    let listener = TcpListener::bind(&normalized)
        .map_err(|e| EcError::Runtime(format!("socks bind failed on {bind_addr}: {e}")))?;

    loop {
        let (stream, _peer) = match listener.accept() {
            Ok(v) => v,
            Err(_) => continue,
        };
        thread::spawn(move || {
            let _ = handle_client(stream);
        });
    }
}

fn normalize_bind_addr(bind_addr: &str) -> String {
    if bind_addr.starts_with(':') {
        format!("0.0.0.0{bind_addr}")
    } else {
        bind_addr.to_string()
    }
}

fn handle_client(mut client: TcpStream) -> EcResult<()> {
    negotiate_method(&mut client)?;
    let target = read_connect_request(&mut client)?;
    let remote = TcpStream::connect(&target)
        .map_err(|e| EcError::Runtime(format!("connect target failed: {target}: {e}")))?;
    write_reply(&mut client, 0x00)?;
    relay(client, remote)
}

fn negotiate_method(client: &mut TcpStream) -> EcResult<()> {
    let mut head = [0u8; 2];
    client
        .read_exact(&mut head)
        .map_err(|e| EcError::Runtime(format!("socks hello read failed: {e}")))?;
    if head[0] != 0x05 {
        return Err(EcError::Runtime("unsupported socks version".to_string()));
    }

    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    client
        .read_exact(&mut methods)
        .map_err(|e| EcError::Runtime(format!("socks methods read failed: {e}")))?;

    if methods.contains(&0x00) {
        client
            .write_all(&[0x05, 0x00])
            .map_err(|e| EcError::Runtime(format!("socks method reply failed: {e}")))?;
        return Ok(());
    }

    client
        .write_all(&[0x05, 0xff])
        .map_err(|e| EcError::Runtime(format!("socks method reject reply failed: {e}")))?;
    Err(EcError::Runtime(
        "client does not support no-auth method".to_string(),
    ))
}

fn read_connect_request(client: &mut TcpStream) -> EcResult<String> {
    let mut req = [0u8; 4];
    client
        .read_exact(&mut req)
        .map_err(|e| EcError::Runtime(format!("socks request head read failed: {e}")))?;

    if req[0] != 0x05 {
        return Err(EcError::Runtime("invalid socks request version".to_string()));
    }
    if req[1] != 0x01 {
        let _ = write_reply(client, 0x07);
        return Err(EcError::Runtime(
            "only CONNECT command is supported".to_string(),
        ));
    }
    if req[2] != 0x00 {
        let _ = write_reply(client, 0x01);
        return Err(EcError::Runtime("invalid socks reserved byte".to_string()));
    }

    let host = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv4 failed: {e}")))?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            client
                .read_exact(&mut len)
                .map_err(|e| EcError::Runtime(format!("read domain length failed: {e}")))?;
            let mut domain = vec![0u8; len[0] as usize];
            client
                .read_exact(&mut domain)
                .map_err(|e| EcError::Runtime(format!("read domain failed: {e}")))?;
            String::from_utf8(domain)
                .map_err(|e| EcError::Runtime(format!("invalid domain utf8: {e}")))?
        }
        0x04 => {
            let mut ip = [0u8; 16];
            client
                .read_exact(&mut ip)
                .map_err(|e| EcError::Runtime(format!("read ipv6 failed: {e}")))?;
            Ipv6Addr::from(ip).to_string()
        }
        atyp => {
            let _ = write_reply(client, 0x08);
            return Err(EcError::Runtime(format!(
                "unsupported socks atyp: 0x{atyp:02x}"
            )));
        }
    };

    let mut port_buf = [0u8; 2];
    client
        .read_exact(&mut port_buf)
        .map_err(|e| EcError::Runtime(format!("read target port failed: {e}")))?;
    let port = u16::from_be_bytes(port_buf);
    Ok(format!("{host}:{port}"))
}

fn write_reply(client: &mut TcpStream, rep: u8) -> EcResult<()> {
    let reply = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    client
        .write_all(&reply)
        .map_err(|e| EcError::Runtime(format!("socks reply write failed: {e}")))
}

fn relay(mut client: TcpStream, remote: TcpStream) -> EcResult<()> {
    let mut c_to_r_src = client
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone client stream failed: {e}")))?;
    let mut c_to_r_dst = remote
        .try_clone()
        .map_err(|e| EcError::Runtime(format!("clone remote stream failed: {e}")))?;
    let mut r_to_c_src = remote;

    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut c_to_r_src, &mut c_to_r_dst);
        let _ = c_to_r_dst.shutdown(Shutdown::Write);
    });
    let t2 = thread::spawn(move || {
        let _ = std::io::copy(&mut r_to_c_src, &mut client);
        let _ = client.shutdown(Shutdown::Write);
    });

    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}
