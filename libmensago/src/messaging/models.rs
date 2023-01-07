use crate::*;
use libkeycard::*;
use std::str::FromStr;

/// MessageModel represents a Mensago message
#[derive(Debug)]
pub struct MessageModel {
    pub id: RandomID,
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

impl MessageModel {
    /// Returns a new message
    pub fn new(from: &WAddress, to: &WAddress, format: DocFormat) -> MessageModel {
        MessageModel {
            id: RandomID::generate(),
            from: from.clone(),
            to: to.clone(),
            cc: Vec::new(),
            bcc: Vec::new(),
            date: Timestamp::new(),
            format,
            thread_id: RandomID::generate(),
            subject: String::new(),
            body: String::new(),
            images: Vec::new(),
            attachments: Vec::new(),
        }
    }

    /// Returns a copy of the current message. Note that the new message will not have the same
    /// message ID as the original
    pub fn clone(&self) -> MessageModel {
        MessageModel {
            id: RandomID::generate(),
            from: self.from.clone(),
            to: self.to.clone(),
            cc: self.cc.clone(),
            bcc: self.bcc.clone(),
            date: self.date.clone(),
            format: self.format.clone(),
            thread_id: self.thread_id.clone(),
            subject: self.subject.clone(),
            body: self.body.clone(),
            images: self.images.clone(),
            attachments: self.attachments.clone(),
        }
    }

    /// Creates a reply to a source message. If quoting is not Quoting::None, each line in the
    /// source message's body is indented with the same formatting as e-mail (`> `). The body format
    /// from the previous message is retained. Pictures are retained if the message is quoted, but
    /// not other attachments.
    pub fn reply(msg: &MessageModel, quoting: QuoteType, reply_all: bool) -> MessageModel {
        let subject = if msg.subject.to_lowercase().starts_with("re:") {
            msg.subject.clone()
        } else {
            format!("Re: {}", msg.subject)
        };

        let body = match quoting {
            QuoteType::None => msg.body.clone(),
            _ => {
                if msg.body.len() == 0 {
                    String::new()
                } else {
                    let lines: Vec<&str> = msg.subject.split("\r\n").collect();
                    lines
                        .iter()
                        .map(|x| format!("> {}", x))
                        .collect::<Vec<String>>()
                        .join("\r\n")
                }
            }
        };

        MessageModel {
            id: RandomID::generate(),
            from: msg.to.clone(),
            to: msg.from.clone(),
            cc: if reply_all {
                msg.cc.clone()
            } else {
                Vec::new()
            },
            bcc: if reply_all {
                msg.bcc.clone()
            } else {
                Vec::new()
            },
            date: Timestamp::new(),
            format: msg.format,
            thread_id: msg.thread_id.clone(),
            subject,
            body,
            images: msg.images.clone(),
            attachments: Vec::new(),
        }
    }

    /// Forwards a source message. As with `reply()`, if quoting is not Quoting::None, each line in
    /// the source message's body is indented and both the body format from the previous message
    /// and any pictures are retained.
    pub fn forward(
        from: &WAddress,
        to: &WAddress,
        msg: &MessageModel,
        quoting: QuoteType,
    ) -> MessageModel {
        let subject = if msg.subject.to_lowercase().starts_with("fwd:") {
            msg.subject.clone()
        } else {
            format!("Fwd: {}", msg.subject)
        };

        let body = match quoting {
            QuoteType::None => msg.body.clone(),
            _ => {
                if msg.body.len() == 0 {
                    String::new()
                } else {
                    let lines: Vec<&str> = msg.subject.split("\r\n").collect();
                    lines
                        .iter()
                        .map(|x| format!("> {}", x))
                        .collect::<Vec<String>>()
                        .join("\r\n")
                }
            }
        };

        MessageModel {
            id: RandomID::generate(),
            from: from.clone(),
            to: to.clone(),
            cc: Vec::new(),
            bcc: Vec::new(),
            date: Timestamp::new(),
            format: msg.format,
            thread_id: msg.thread_id.clone(),
            subject,
            body,
            images: msg.images.clone(),
            attachments: Vec::new(),
        }
    }

    // Sets the message subject
    pub fn set_subject(mut self, subject: &str) -> Self {
        self.subject = String::from(subject);
        self
    }

    // Sets the message body
    pub fn set_body(mut self, body: &str) -> Self {
        self.subject = String::from(body);
        self
    }

    // Adds a CC recipient
    pub fn add_cc(mut self, recipient: WAddress) -> Self {
        self.cc.push(recipient);
        self
    }

    // Removes all CC recipients
    pub fn clear_cc(mut self) -> Self {
        self.cc.clear();
        self
    }

    // Adds a BCC recipient
    pub fn add_bcc(mut self, recipient: WAddress) -> Self {
        self.bcc.push(recipient);
        self
    }

    // Removes all BCC recipients
    pub fn clear_bcc(mut self) -> Self {
        self.bcc.clear();
        self
    }

    // Adds an image
    pub fn add_image(mut self, img: ImageModel) -> Self {
        self.images.push(img);
        self
    }

    // Removes all images
    pub fn clear_images(mut self) -> Self {
        self.images.clear();
        self
    }

    // Adds an attachment
    pub fn attach(mut self, attachment: AttachmentModel) -> Self {
        self.attachments.push(attachment);
        self
    }

    // Removes all attachments
    pub fn clear_attachments(mut self) -> Self {
        self.attachments.clear();
        self
    }
}

impl DBModel for MessageModel {
    fn delete_from_db(&self, conn: &mut DBConn) -> Result<(), MensagoError> {
        conn.execute("DELETE FROM messages WHERE id=?1", &[&self.id.to_string()])
    }

    fn refresh_from_db(&mut self, conn: &mut DBConn) -> Result<(), MensagoError> {
        let values = conn.query(
            "SELECT from,to,cc,bcc,date,format,thread_id,subject,body FROM messages 
            WHERE id = ?1",
            &[&self.id.to_string()],
        )?;
        if values.len() != 1 {
            return Err(MensagoError::ErrNotFound);
        }
        if values[0].len() != 10 {
            return Err(MensagoError::ErrSchemaFailure);
        }
        let fromstr = values[0][0].to_string();
        let conidstr = values[0][1].to_string();
        let tostr = values[0][2].to_string();
        let ccstr = values[0][3].to_string();
        let bccstr = values[0][4].to_string();
        let datestr = values[0][5].to_string();
        let formatstr = values[0][6].to_string();
        let thridstr = values[0][7].to_string();
        let subject = values[0][8].to_string();
        let body = values[0][9].to_string();

        self.from = match WAddress::from(&fromstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad From: address received from database: '{}'",
                    fromstr
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

    fn set_in_db(&self, conn: &mut DBConn) -> Result<(), MensagoError> {
        let ccstr = SeparatedStrList::from_vec(&self.cc, ",").join();
        let bccstr = SeparatedStrList::from_vec(&self.bcc, ",").join();

        conn.execute(
            "INSERT OR REPLACE INTO 
            messages(id,from,to,cc,bcc,date,format,thread_id,subject,body)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            &[
                &self.id.to_string(),
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
        )
    }
}
