use crate::base::*;
use libkeycard::*;
use std::net::TcpStream;

pub fn getwid(conn: &mut TcpStream, uid: &UserID, domain: &Domain)
-> Result<RandomID, MensagoError> {

	Err(MensagoError::ErrUnimplemented)
}