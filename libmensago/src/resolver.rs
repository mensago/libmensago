use crate::*;
use eznacl::CryptoString;
use libkeycard::*;

/// This function attempts to obtain Mensago server configuration information for the specified
/// domain using the process documented in the spec:
///
/// 1. Check for an SRV record with the service type `_mensago._tcp`, and use the supplied FQDN
/// and port if it exists
/// 2. Perform an A or AAAA lookup for `mensago.subdomain.example.com`
/// 3. Perform an A or AAAA lookup for `mensago.example.com`
/// 4. Attempt to connect to `example.com`
///
/// If all of these checks fail, then the domain is assumed to not offer Mensago services and
/// MensagoError::ErrNotFound will be returned.
pub fn get_server_config<DH>(
    d: &Domain,
    dh: &mut DH,
) -> Result<Vec<ServiceConfigRecord>, MensagoError>
where
    DH: DNSHandlerT + ?Sized,
{
    match dh.lookup_srv(&format!("_mensago._tcp.{}", d.as_string())) {
        Ok(v) => return Ok(v),
        Err(_) => (),
    };

    let mut tempdom = d.clone();
    loop {
        tempdom.push("mensago").unwrap();

        match dh.lookup_a(&d) {
            Ok(_) => {
                return Ok(vec![ServiceConfigRecord {
                    server: tempdom.clone(),
                    port: 2001,
                    priority: 0,
                }])
            }
            Err(_) => (),
        }

        match dh.lookup_aaaa(&d) {
            Ok(_) => {
                return Ok(vec![ServiceConfigRecord {
                    server: tempdom.clone(),
                    port: 2001,
                    priority: 0,
                }])
            }
            Err(_) => (),
        }

        tempdom.pop().unwrap();

        if tempdom.parent().is_none() {
            break;
        }

        tempdom.pop().unwrap();
    }

    // Having gotten this far, we have only one other option: attempt to connect to the domain
    // on port 2001.
    let mut conn = ServerConnection::new();
    match conn.connect(tempdom.as_string(), 2001) {
        Ok(_) => {
            return Ok(vec![ServiceConfigRecord {
                server: tempdom.clone(),
                port: 2001,
                priority: 0,
            }])
        }
        Err(_) => (),
    }

    Err(MensagoError::ErrNotFound)
}

pub struct DNSMgmtRecord {
    pub pvk: CryptoString,
    pub svk: Option<CryptoString>,
    pub ek: CryptoString,
    pub tls: Option<CryptoString>,
}

pub fn get_mgmt_record<DH>(d: &Domain, dh: &mut DH) -> Result<DNSMgmtRecord, MensagoError>
where
    DH: DNSHandlerT + ?Sized,
{
    let domstr = d.to_string();
    let domparts: Vec<&str> = domstr.split(".").collect();

    // This is probably a hostname, so we'll check just the hostname for records
    if domparts.len() == 1 {
        return parse_txt_records(&mut dh.lookup_txt(d)?);
    }

    let mut out: Option<DNSMgmtRecord> = None;
    for i in 0..domparts.len() - 1 {
        let mut testparts = vec!["mensago"];
        for i in i..domparts.len() {
            testparts.push(domparts[i])
        }

        let testdom = match Domain::from(&testparts.join(".")) {
            Some(v) => v,
            None => return Err(MensagoError::ErrBadValue),
        };

        let records = match dh.lookup_txt(&testdom) {
            Ok(v) => v,
            Err(_) => continue,
        };

        out = Some(parse_txt_records(&records)?);
    }

    match out {
        Some(v) => Ok(v),
        None => Err(MensagoError::ErrNotFound),
    }
}

// This private function just finds the management record items in a list of TXT records
fn parse_txt_records(records: &Vec<String>) -> Result<DNSMgmtRecord, MensagoError> {
    // This seemlingly pointless construct ensures that we have all the necessary information if,
    // say, the admin put 2 management record items in a TXT record and put another in a second
    // record because they ran out of space in the first one
    let recordstr = records.join(" ");
    let parts = recordstr.split(" ");

    // The four possible record items. The PVK and EK items are required.
    let mut pvk: Option<CryptoString> = None;
    let mut svk: Option<CryptoString> = None;
    let mut ek: Option<CryptoString> = None;
    let mut tls: Option<CryptoString> = None;
    for part in parts {
        if part.len() < 5 {
            return Err(MensagoError::ErrBadValue);
        }

        match part {
            x if x.to_lowercase().starts_with("pvk=") => pvk = CryptoString::from(&x[4..]),
            x if x.to_lowercase().starts_with("svk=") => svk = CryptoString::from(&x[4..]),
            x if x.to_lowercase().starts_with("ek=") => ek = CryptoString::from(&x[3..]),
            x if x.to_lowercase().starts_with("tls=") => tls = CryptoString::from(&x[4..]),
            _ => (),
        }
    }

    if pvk.is_none() || ek.is_none() {
        return Err(MensagoError::ErrNotFound);
    }

    Ok(DNSMgmtRecord {
        pvk: pvk.unwrap(),
        svk,
        ek: ek.unwrap(),
        tls,
    })
}

/// A caching keycard resolver type
pub struct KCResolver {
    profile: Profile,
}

impl KCResolver {
    /// Creates a new resolver working out of the at the specified profile
    pub fn new(profile: &Profile) -> Result<KCResolver, MensagoError> {
        return Ok(KCResolver {
            profile: profile.clone(),
        });
    }

    /// Returns a keycard belonging to the specified owner. To obtain an organization's keycard,
    /// pass a domain, e.g. `example.com`. Otherwise obtain a user's keycard by passing either the
    /// user's Mensago address or its workspace address. When `force_update` is true, a lookup is
    /// forced and the cache is updated regardless of the keycard's TTL expiration status.
    pub fn get_card<DH>(
        &mut self,
        owner: &str,
        dh: &mut DH,
        force_update: bool,
    ) -> Result<Keycard, MensagoError>
    where
        DH: DNSHandlerT + ?Sized,
    {
        // First, determine the type of owner. A domain will be passed for an organization, and for
        // a user card a Mensago address or a workspace address will be given.
        let domain: Domain;
        let owner_type: EntryType;

        let isorg = Domain::from(owner);
        if isorg.is_some() {
            owner_type = EntryType::Organization;
            domain = isorg.unwrap();
        } else {
            let isuser = MAddress::from(owner);
            if isuser.is_some() {
                owner_type = EntryType::User;
                domain = isuser.unwrap().domain.clone();
            } else {
                return Err(MensagoError::ErrBadValue);
            }
        }

        let dbconn = self.profile.open_storage()?;
        let mut card: Option<Keycard> = None;

        if !force_update {
            card = get_card_from_db(&dbconn, owner, owner_type, true)?;
        }

        // If we got a card from the call, it means a successful cache hit and the TTL timestamp
        // hasn't been reached yet.
        if card.is_some() {
            return Ok(card.unwrap());
        }

        // If we've gotten this far, it means that the card isn't in the database cache, so resolve
        // the card, add it to the database's cache, and return it to the caller.

        let serverconfig = get_server_config(&domain, dh)?;
        if serverconfig.len() == 0 {
            return Err(MensagoError::ErrNoMensago);
        }

        let ip = dh.lookup_a(&serverconfig[0].server)?;

        let mut conn = ServerConnection::new();
        conn.connect(&ip.to_string(), serverconfig[0].port)?;

        let card = match owner_type {
            EntryType::Organization => orgcard(&mut conn, 1)?,
            EntryType::User => usercard(&mut conn, &MAddress::from(owner).unwrap(), 1)?,
            _ => {
                // We should never be here
                panic!("BUG: Bad owner type in KCResolver::get_card()")
            }
        };

        conn.disconnect()?;

        update_keycard_in_db(&dbconn, &card, true)?;
        Ok(card)
    }

    /// Obtains the workspace ID for a Mensago address
    pub fn resolve_address<DH>(
        &mut self,
        addr: &MAddress,
        dh: &mut DH,
    ) -> Result<RandomID, MensagoError>
    where
        DH: DNSHandlerT + ?Sized,
    {
        if addr.get_uid().get_type() == IDType::WorkspaceID {
            return Ok(RandomID::from(addr.get_uid().as_string())
                .expect("BUG: couldn't convert UID to WID in KCResolver::resolve_address()"));
        }

        let serverconfig = get_server_config(addr.get_domain(), dh)?;
        if serverconfig.len() == 0 {
            return Err(MensagoError::ErrNoMensago);
        }

        let ip = dh.lookup_a(&serverconfig[0].server)?;

        let mut conn = ServerConnection::new();

        conn.connect(&ip.to_string(), serverconfig[0].port)?;
        let wid = getwid(&mut conn, addr.get_uid(), Some(addr.get_domain()))?;
        conn.disconnect()?;

        Ok(wid)
    }
}
