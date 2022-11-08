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
