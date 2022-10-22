use crate::{base::*, dbsupport::*, types::DocFormat, AttachmentModel};
use libkeycard::*;
use rusqlite;
use std::str::FromStr;

/// MessageModel represents a Mensago message
#[derive(Debug, Clone)]
pub struct MessageModel {
    pub id: RandomID,
    pub contact_id: RandomID,
    pub from: WAddress,
    pub to: WAddress,
    pub cc: Vec<WAddress>,
    pub bcc: Vec<WAddress>,
    pub date: Timestamp,
    pub format: DocFormat,
    pub thread_id: RandomID,
    pub subject: String,
    pub body: String,
    pub images: Vec<ImageModel>,
    pub attachments: Vec<AttachmentModel>,
}

impl MessageModel {}

impl DBModel for MessageModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute("DELETE FROM messages WHERE id=?1", &[&self.id.to_string()]) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let mut stmt = conn.prepare(
            "SELECT from,conid,to,cc,bcc,date,format,thread_id,subject,body FROM messages 
            WHERE id = ?1",
        )?;
        let (fromstr, conidstr, tostr, ccstr, bccstr, datestr, formatstr, thridstr, subject, body) =
            match stmt.query_row(&[&self.id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                    row.get::<usize, String>(5).unwrap(),
                    row.get::<usize, String>(6).unwrap(),
                    row.get::<usize, String>(7).unwrap(),
                    row.get::<usize, String>(8).unwrap(),
                    row.get::<usize, String>(9).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };
        drop(stmt);

        self.from = match WAddress::from(&fromstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad From: address received from database: '{}'",
                    fromstr
                )))
            }
        };
        self.contact_id = match RandomID::from(&conidstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad contact ID received from database: '{}'",
                    conidstr
                )))
            }
        };
        self.to = match WAddress::from(&tostr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad To: address received from database: '{}'",
                    tostr
                )))
            }
        };

        let addrlist = SeparatedStrList::from(&ccstr, ",");
        self.cc = Vec::new();
        for item in addrlist.items {
            match WAddress::from(&item) {
                Some(v) => self.cc.push(v),
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad CC: address received from database: '{}'",
                        item
                    )))
                }
            };
        }

        let addrlist = SeparatedStrList::from(&bccstr, ",");
        self.bcc = Vec::new();
        for item in addrlist.items {
            match WAddress::from(&item) {
                Some(v) => self.bcc.push(v),
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad BCC: address received from database: '{}'",
                        item
                    )))
                }
            };
        }

        self.date = match Timestamp::from_str(&datestr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad timestamp received from database: '{}'",
                    datestr
                )))
            }
        };
        self.format = match DocFormat::from_str(&formatstr) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad format value received from database: '{}'",
                    formatstr
                )))
            }
        };
        self.thread_id = match RandomID::from(&thridstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad thread ID received from database: '{}'",
                    conidstr
                )))
            }
        };
        self.subject = subject;
        self.body = body;
        self.images = ImageModel::load_all(&self.id, conn)?;
        self.attachments = AttachmentModel::load_all(&self.id, conn)?;

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let ccstr = SeparatedStrList::from_vec(&self.cc, ",").join();
        let bccstr = SeparatedStrList::from_vec(&self.bcc, ",").join();

        match conn.execute(
            "INSERT OR REPLACE INTO 
            messages(id,from,conid,to,cc,bcc,date,format,thread_id,subject,body)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            &[
                &self.id.to_string(),
                &self.contact_id.to_string(),
                &self.from.to_string(),
                &self.to.to_string(),
                &ccstr,
                &bccstr,
                &self.date.to_string(),
                &self.format.to_string(),
                &self.thread_id.to_string(),
                &self.subject,
                &self.body,
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}
