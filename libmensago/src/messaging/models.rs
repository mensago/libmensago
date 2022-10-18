use crate::{base::*, dbsupport::*, types::DocFormat, AttachmentModel};
use libkeycard::*;
use rusqlite;

/// MessageModel represents a Mensago message
#[derive(Debug, Clone)]
pub struct MessageModel {
    pub id: RandomID,
    pub contact_id: RandomID,
    pub from: WAddress,
    pub to: WAddress,
    pub cc: SeparatedStrList,
    pub bcc: SeparatedStrList,
    pub date: Timestamp,
    pub format: DocFormat,
    pub thread_id: RandomID,
    pub subject: String,
    pub body: String,
    //pub images: Vec<ImageModel>,
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
            "SELECT from,conid,to,cc,bcc,date,format,thread_id,subject,body,
			images,attachments FROM messages WHERE id = ?1",
        )?;
        let (
            fromst,
            conidstr,
            tostr,
            ccstr,
            bccstr,
            datestr,
            formatstr,
            thridstr,
            subject,
            body,
            imagestr,
            attstr,
        ) = match stmt.query_row(&[&self.id.to_string()], |row| {
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
                row.get::<usize, String>(10).unwrap(),
                row.get::<usize, String>(11).unwrap(),
            ))
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
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

        // TODO: Finish MessageModel::refresh_from_db()

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        // match conn.execute(
        //     "INSERT OR REPLACE INTO messages(id,itemtype,conid,label,value)
        //     VALUES(?1,?2,?3,?4,?5)",
        //     &[
        //         &self.id.to_string(),
        //         &self.itemtype.to_string(),
        //         &self.contact_id.to_string(),
        //         &self.label,
        //         &self.value,
        //     ],
        // ) {
        //     Ok(_) => Ok(()),
        //     Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        // }
        // TODO: Implement MessageModel::set_in_db()
        Err(MensagoError::ErrUnimplemented)
    }
}
