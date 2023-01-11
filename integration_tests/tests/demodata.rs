use libmensago::*;
use libmensago::{DBModel, MensagoError};

pub fn import_demonotes(db: &mut DBConn) -> Result<(), MensagoError> {
    let mut txtnote = NoteModel::new("The Pilgrim's Progress", DocFormat::Text, "Default");
    txtnote.body = String::from(DEMO_NOTE_TXT);
    txtnote.set_in_db(db)?;

    let mut mdnote = NoteModel::new("Dartpass: README", DocFormat::Markdown, "Default");
    mdnote.body = String::from(DEMO_NOTE_MD);
    mdnote.set_in_db(db)?;

    let mut sftmnote = NoteModel::new("The Road Not Taken", DocFormat::SFTM, "SFTM");
    sftmnote.body = String::from(DEMO_NOTE_SFTM);
    sftmnote.set_in_db(db)?;

    Ok(())
}

mod tests {
    use super::import_demonotes;
    use crate::common::*;
    use libmensago::MensagoError;

    #[test]
    fn test_load_demonotes() -> Result<(), MensagoError> {
        let testname = "test_load_demonotes";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, mut profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile_mut().unwrap();
        let mut db = match profile.get_db() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: new db conn failed to connect: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match import_demonotes(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error importing demo notes: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        Ok(())
    }
}

static DEMO_NOTE_TXT: &str = r"
THE PILGRIM'S PROGRESS

From This World To That Which Is To Come

by

John Bunyan


Part One

DELIVERED UNDER THE SIMILITUDE OF A DREAM BY JOHN BUNYAN


The Author's Apology for his Book

When at the first I took my pen in hand
  Thus for to write, I did not understand
  That I at all should make a little book
  In such a mode; nay, I had undertook
  To make another; which, when almost done,
  Before I was aware, I this begun.

  And thus it was: I, writing of the way
  And race of saints, in this our gospel day,
  Fell suddenly into an allegory
  About their journey, and the way to glory,
  In more than twenty things which I set down.
  This done, I twenty more had in my crown;
  And they again began to multiply,
  Like sparks that from the coals of fire do fly.

  Nay, then, thought I, if that you breed so fast,
  I'll put you by yourselves, lest you at last
  Should prove ad infinitum, and eat out
  The book that I already am about.

  Well, so I did; but yet I did not think
  To shew to all the world my pen and ink
  In such a mode; I only thought to make
  I knew not what; nor did I undertake
  Thereby to please my neighbour: no, not I;
  I did it my own self to gratify.
  ";

static DEMO_NOTE_MD: &str = r"
# Dartpass

Dartpass is a flexible command-line password generator designed for power users and administrators, written in Dart, and released under the Mozilla Public License 2.0.

## Description

Most password generators simply jam together a bunch of random characters and call it a day. They also give you options to choose the length and which characters it will use to generate them with. Others use the [diceware](https://diceware.dmuth.org/) algorithm straight out of the box or with a custom word list. This is a much better option because most people are terrible at remembering passwords and a certain amount of computer literacy is needed to use a password manager. Rather than choosing `Spring2022` for the fiftieth time with the hopes that the user will actually choose a decent password, dartpass gives you options to create customized passphrases that vary in levels of security, not insecurity.

## Usage

Dartpass leverages the [Electronic Frontier Foundation's](https://www.eff.org/) [primary word list](https://www.eff.org/document/passphrase-wordlists) as the source and, by default, uses 4 words with capitalization. This achieves the best ratings from both [How Secure Is My Password](https://www.security.org/how-secure-is-my-password/) and Dropbox's [zxcvbn](https://github.com/dropbox/zxcvbn) algorithm. You can choose more or fewer words, add in numbers or symbols, place limits on word length, exclude hard-to-type characters, or just generate a random-character password.

### Examples

- `dartpass --count 10 --addnumber=1 --addsymbol=1` -> generate 10 passphrases consisting of 4 words, a number, and a symbol
- `dartpass --chars --size 12 --nosymbols ` -> generate 5 12-character passphrases consisting only of letters and numbers
- `dartpass --size 4 --min=4 --max=6` -> generate 5 passphrases consisting of 4 4-6 letter words.

### Options

```
-h, --help                    Displays this message
    --version                 Displays version information

-c, --count=<n>               Number of passphrases to generate. Defaults to 5.
-s, --size=<n>                Number of words or characters in the passphrase. Defaults to 4 words or 8 characters.
-e, --easysymbols             Exclude symbols which often confuse non-technical users: braces, brackets, backslash, backtick, and the pipe symbol.
-x, --exclude=<charstring>    A string of other characters to exclude from passphrases.

    --chars                   Use individual characters instead of words for passphrase generation.
    --nosymbols               Don't use symbols in character-based passphrases
    --nonumbers               Don't use numbers in character-based passphrases

    --nocapitalize            Don't capitalize the first letter of each word in word-based passphrases.
    --min=<n>                 Set minimum word length in word-based passphrases.
    --max=<n>                 Set maximum word length in word-based passphrases.
    --addnumber=<n>           Add n numbers to word-based passphrases.
    --addsymbol=<n>           Add n symbols to word-based passphrases.
```
### Contributions

This is my first Dart project, so I'm pretty sure things aren't optimal even if they work well enough. Contributions are always welcome.
";

static DEMO_NOTE_SFTM: &str = "
[document type=\"sftm\" version=\"1.0\"][body]
[h1]The Road Not Taken[/h1]
[h2]By Robert Frost[/h2]

[p]Two roads diverged in a yellow wood,
And sorry I could not travel both
And be one traveler, long I stood
And looked down one as far as I could
To where it bent in the undergrowth;[/p]

[p]Then took the other, as just as fair,
And having perhaps the better claim,
Because it was grassy and wanted wear;
Though as for that the passing there
Had worn them really about the same,[/p]

[p]And both that morning equally lay
In leaves no step had trodden black.
Oh, I kept the first for another day!
Yet knowing how way leads on to way,
I doubted if I should ever come back.[/p]

[p]I shall be telling this with a sigh
Somewhere ages and ages hence:
Two roads diverged in a wood, and I—
I took the one less traveled by,
And that has made all the difference.[/p]
[/body][/document]
";
