//! A small ELIZA in the style of Weizenbaum's DOCTOR script. A
//! [`Conversation`] takes a line and returns a reply.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// What the doctor says first.
pub const GREETING: &str = "How do you do. Please tell me your problem.";

const MAX_MEMORY: usize = 8;
/// Bounds the words matched: `*` patterns backtrack, so matching grows
/// with a power of the word count.
const MAX_WORDS: usize = 100;

/// One conversation. It rotates through each decomposition's reassemblies
/// and remembers things the user said about themselves to bring up later.
#[derive(Default)]
pub struct Conversation {
    next: HashMap<(usize, usize), usize>,
    memory: Vec<String>,
}

impl Conversation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answers one line.
    pub fn reply(&mut self, input: &str) -> String {
        let script = &*SCRIPT;
        let mut words = script.normalize(input);
        words.truncate(MAX_WORDS);
        if words.is_empty() {
            return "Please say something.".into();
        }
        if words.iter().any(|w| script.quits.contains(w)) {
            return "Goodbye. Thank you for talking to me.".into();
        }
        for k in script.keywords_in(&words) {
            if let Some(r) = self.apply(k, &words) {
                return r;
            }
        }
        if !self.memory.is_empty() {
            return self.memory.remove(0);
        }
        self.apply(script.fallback, &words).unwrap_or_else(|| "Please go on.".into())
    }

    fn apply(&mut self, key: usize, words: &[String]) -> Option<String> {
        let script = &*SCRIPT;
        for (di, d) in script.keys[key].decomps.iter().enumerate() {
            let Some(parts) = matches(script, &d.pattern, words) else { continue };
            if let Some(target) = &d.goto {
                return self.apply(script.by_name[target.as_str()], words);
            }
            let n = self.next.entry((key, di)).or_default();
            let template = &d.reasm[*n];
            *n = (*n + 1) % d.reasm.len();
            let reply = reassemble(script, template, &parts);
            if d.memorize {
                if self.memory.len() < MAX_MEMORY {
                    self.memory.push(reply);
                }
                continue;
            }
            return Some(reply);
        }
        None
    }
}

fn reassemble(script: &Script, template: &str, parts: &[Vec<String>]) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('(') {
        let close = rest[open..].find(')').map(|c| open + c);
        let n = close.and_then(|c| rest[open + 1..c].parse::<usize>().ok());
        match (close, n) {
            (Some(close), Some(n)) if n >= 1 => {
                out.push_str(&rest[..open]);
                if let Some(p) = parts.get(n - 1) {
                    out.push_str(&script.reflect(p));
                }
                rest = &rest[close + 1..];
            }
            _ => {
                out.push_str(&rest[..=open]);
                rest = &rest[open + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Matches words against a pattern of literal words, `*` (any run of words,
/// possibly empty) and `@set` (one word from a synonym set). Returns the
/// words each `*` and `@set` captured, in order.
fn matches(script: &Script, pattern: &[String], words: &[String]) -> Option<Vec<Vec<String>>> {
    let Some((p, pattern_rest)) = pattern.split_first() else {
        return words.is_empty().then(Vec::new);
    };
    if p == "*" {
        for n in 0..=words.len() {
            if let Some(mut rest) = matches(script, pattern_rest, &words[n..]) {
                rest.insert(0, words[..n].to_vec());
                return Some(rest);
            }
        }
        return None;
    }
    let (w, words_rest) = words.split_first()?;
    if let Some(set) = p.strip_prefix('@') {
        if !script.synonyms.get(set).is_some_and(|s| s.contains(w)) {
            return None;
        }
        let mut rest = matches(script, pattern_rest, words_rest)?;
        rest.insert(0, vec![w.clone()]);
        return Some(rest);
    }
    if p == w { matches(script, pattern_rest, words_rest) } else { None }
}

struct Decomp {
    pattern: Vec<String>,
    reasm: Vec<String>,
    goto: Option<String>,
    memorize: bool,
}

struct Key {
    rank: i32,
    decomps: Vec<Decomp>,
}

struct Script {
    pre: HashMap<String, Vec<String>>,
    post: HashMap<String, String>,
    synonyms: HashMap<String, HashSet<String>>,
    quits: HashSet<String>,
    keys: Vec<Key>,
    by_word: HashMap<String, usize>,
    by_name: HashMap<String, usize>,
    fallback: usize,
}

impl Script {
    fn normalize(&self, input: &str) -> Vec<String> {
        let cleaned: String = input
            .to_lowercase()
            .replace('’', "'")
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '\'' { c } else { ' ' })
            .collect();
        let mut out = Vec::new();
        for w in cleaned.split_whitespace() {
            match self.pre.get(w) {
                Some(p) => out.extend(p.iter().cloned()),
                None => out.push(w.to_string()),
            }
        }
        out
    }

    /// The script's keywords found in words, highest rank first, ties in
    /// order of appearance.
    fn keywords_in(&self, words: &[String]) -> Vec<usize> {
        let mut found: Vec<usize> = Vec::new();
        for w in words {
            if let Some(&k) = self.by_word.get(w)
                && !found.contains(&k)
            {
                found.push(k);
            }
        }
        found.sort_by_key(|&k| std::cmp::Reverse(self.keys[k].rank));
        found
    }

    fn reflect(&self, words: &[String]) -> String {
        words.iter().map(|w| self.post.get(w).unwrap_or(w).as_str()).collect::<Vec<_>>().join(" ")
    }
}

static SCRIPT: LazyLock<Script> = LazyLock::new(|| load(SCRIPT_TEXT).expect("the built-in script is valid"));

fn last_decomp(s: &mut Script, line: usize) -> Result<&mut Decomp, String> {
    s.keys.last_mut().and_then(|k| k.decomps.last_mut()).ok_or_else(|| format!("script line {}: no decomposition", line + 1))
}

fn load(text: &str) -> Result<Script, String> {
    let mut s = Script {
        pre: HashMap::new(),
        post: HashMap::new(),
        synonyms: HashMap::new(),
        quits: HashSet::new(),
        keys: Vec::new(),
        by_word: HashMap::new(),
        by_name: HashMap::new(),
        fallback: 0,
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (dir, arg) = line.split_once(':').ok_or_else(|| format!("script line {}: no directive", n + 1))?;
        let arg = arg.trim();
        let f: Vec<String> = arg.split_whitespace().map(String::from).collect();
        match dir {
            "pre" => {
                s.pre.insert(f[0].clone(), f[1..].to_vec());
            }
            "post" => {
                s.post.insert(f[0].clone(), f[1].clone());
            }
            "synon" => {
                s.synonyms.insert(f[0].clone(), f.iter().cloned().collect());
            }
            "quit" => {
                s.quits.insert(f[0].clone());
            }
            "key" => {
                let rank = f[1].parse().map_err(|e| format!("script line {}: {e}", n + 1))?;
                let names: Vec<&str> = f[0].split('|').collect();
                let id = s.keys.len();
                s.keys.push(Key { rank, decomps: Vec::new() });
                s.by_name.insert(names[0].to_string(), id);
                for w in names {
                    s.by_word.insert(w.to_string(), id);
                }
            }
            "decomp" => {
                let key = s.keys.last_mut().ok_or_else(|| format!("script line {}: decomp before any key", n + 1))?;
                let memorize = f.first().is_some_and(|w| w == "$");
                let pattern = if memorize { f[1..].to_vec() } else { f };
                key.decomps.push(Decomp { pattern, reasm: Vec::new(), goto: None, memorize });
            }
            "reasmb" => last_decomp(&mut s, n)?.reasm.push(arg.to_string()),
            "goto" => last_decomp(&mut s, n)?.goto = Some(arg.to_string()),
            _ => return Err(format!("script line {}: unknown directive {dir:?}", n + 1)),
        }
    }
    for k in &s.keys {
        for d in &k.decomps {
            match &d.goto {
                Some(t) if !s.by_name.contains_key(t) => return Err(format!("goto unknown key {t}")),
                None if d.reasm.is_empty() => return Err("decomposition without reassembly".into()),
                _ => {}
            }
        }
    }
    s.fallback = *s.by_name.get("xnone").ok_or("no xnone key")?;
    Ok(s)
}

// The script. Lines are "directive: arguments":
//
//   pre: from to...      rewrite a word on input
//   post: from to        reflect a word when it is echoed back
//   synon: name w...     a synonym set, matched in patterns as @name
//   quit: w              a word that ends the conversation
//   key: w[|alias] rank  a keyword; the decomps that follow belong to it
//   decomp: pattern      a decomposition; "$ pattern" is memorized instead
//   reasmb: text         a reassembly; (n) is the nth captured part
//   goto: key            try another keyword's decomps instead
const SCRIPT_TEXT: &str = r#"
pre: dont don't
pre: cant can't
pre: wont won't
pre: im i am
pre: i'm i am
pre: youre you are
pre: you're you are
pre: recollect remember
pre: dreamt dreamed
pre: dreams dream
pre: maybe perhaps
pre: certainly yes
pre: machine computer
pre: machines computer
pre: computers computer
pre: same alike
pre: identical alike
pre: equivalent alike
post: am are
post: are am
post: your my
post: my your
post: me you
post: myself yourself
post: yourself myself
post: i you
post: you I
post: i'm you are
post: you're I am
post: was were
synon: belief feel think believe wish
synon: family mother mom father dad sister brother wife husband children child son daughter
synon: desire want need
synon: sad unhappy depressed sick miserable lonely
synon: happy elated glad better cheerful
synon: cannot can't
synon: everyone everybody nobody noone
synon: be am is are was
quit: bye
quit: goodbye
quit: quit

key: xnone -1
decomp: *
reasmb: I'm not sure I understand you fully.
reasmb: Please go on.
reasmb: What does that suggest to you?
reasmb: Do you feel strongly about discussing such things?
reasmb: That is interesting. Please continue.
reasmb: Tell me more about that.

key: sorry 0
decomp: *
reasmb: Please don't apologise.
reasmb: Apologies are not necessary.
reasmb: What feelings do you have when you apologise?

key: apologise|apologize 0
decomp: *
goto: sorry

key: remember 5
decomp: * i remember *
reasmb: Do you often think of (2)?
reasmb: Does thinking of (2) bring anything else to mind?
reasmb: Why do you remember (2) just now?
reasmb: What in the present situation reminds you of (2)?
decomp: * do you remember *
reasmb: Did you think I would forget (2)?
reasmb: Why do you think I should recall (2) now?
reasmb: What about (2)?
decomp: *
goto: xnone

key: if 3
decomp: * if *
reasmb: Do you think it's likely that (2)?
reasmb: Do you wish that (2)?
reasmb: What do you know about (2)?
reasmb: Really, if (2)?

key: dreamed 4
decomp: * i dreamed *
reasmb: Really, (2)?
reasmb: Have you ever fantasized (2) while you were awake?
reasmb: Have you ever dreamed (2) before?
decomp: *
goto: dream

key: dream 3
decomp: *
reasmb: What does that dream suggest to you?
reasmb: Do you dream often?
reasmb: What persons appear in your dreams?
reasmb: Do you believe that dreams have something to do with your problem?

key: perhaps 0
decomp: *
reasmb: You don't seem quite certain.
reasmb: Why the uncertain tone?
reasmb: Can't you be more positive?
reasmb: You aren't sure?

key: name 15
decomp: *
reasmb: I am not interested in names.
reasmb: I've told you before, I don't care about names. Please continue.

key: computer 50
decomp: *
reasmb: Do computers worry you?
reasmb: Why do you mention computers?
reasmb: What do you think machines have to do with your problem?
reasmb: Don't you think computers can help people?
reasmb: What about machines worries you?

key: am 0
decomp: * am i *
reasmb: Do you believe you are (2)?
reasmb: Would you want to be (2)?
reasmb: Do you wish I would tell you you are (2)?
decomp: *
goto: xnone

key: are 0
decomp: * are you *
reasmb: Why are you interested in whether I am (2) or not?
reasmb: Would you prefer if I weren't (2)?
reasmb: Perhaps I am (2) in your fantasies.
decomp: * are *
reasmb: Did you think they might not be (2)?
reasmb: Possibly they are (2).

key: your 0
decomp: * your *
reasmb: Why are you concerned over my (2)?
reasmb: What about your own (2)?
reasmb: Are you worried about someone else's (2)?

key: was 2
decomp: * was i *
reasmb: What if you were (2)?
reasmb: Do you think you were (2)?
reasmb: What would it mean if you were (2)?
decomp: * i was *
reasmb: Were you really?
reasmb: Why do you tell me you were (2) now?
decomp: * was you *
reasmb: Would you like to believe I was (2)?
reasmb: Perhaps I was (2).
decomp: *
goto: xnone

key: i 0
decomp: * i @desire *
reasmb: What would it mean to you if you got (3)?
reasmb: Why do you want (3)?
reasmb: Suppose you got (3) soon.
decomp: * i am * @sad *
reasmb: I am sorry to hear that you are (3).
reasmb: Do you think coming here will help you not to be (3)?
reasmb: I'm sure it's not pleasant to be (3).
reasmb: Can you explain what made you (3)?
decomp: * i am * @happy *
reasmb: How have I helped you to be (3)?
reasmb: What makes you (3) just now?
reasmb: Can you explain why you are suddenly (3)?
decomp: * i @belief i *
reasmb: Do you really think so?
reasmb: But you are not sure you (3).
reasmb: Do you really doubt you (3)?
decomp: * i am *
reasmb: Is it because you are (2) that you came to me?
reasmb: How long have you been (2)?
reasmb: Do you believe it is normal to be (2)?
reasmb: Do you enjoy being (2)?
decomp: * i @cannot *
reasmb: How do you know that you can't (3)?
reasmb: Have you tried?
reasmb: Perhaps you could (3) now.
reasmb: Do you really want to be able to (3)?
decomp: * i don't *
reasmb: Don't you really (2)?
reasmb: Why don't you (2)?
reasmb: Do you wish to be able to (2)?
decomp: * i feel *
reasmb: Tell me more about such feelings.
reasmb: Do you often feel (2)?
reasmb: Do you enjoy feeling (2)?
decomp: * i * you *
reasmb: Perhaps in your fantasies we (2) each other.
reasmb: Do you wish to (2) me?
reasmb: You seem to need to (2) me.
decomp: *
reasmb: You say (1)?
reasmb: Can you elaborate on that?
reasmb: Do you say (1) for some special reason?
reasmb: That's quite interesting.

key: you 0
decomp: * you remind me of *
goto: alike
decomp: * you are *
reasmb: What makes you think I am (2)?
reasmb: Does it please you to believe I am (2)?
reasmb: Do you sometimes wish you were (2)?
decomp: * you * me *
reasmb: Why do you think I (2) you?
reasmb: You like to think I (2) you, don't you?
reasmb: What makes you think I (2) you?
reasmb: Suppose I did (2) you. What would that mean?
decomp: * you *
reasmb: We were discussing you, not me.
reasmb: Oh, I (2)?
reasmb: You're not really talking about me, are you?
reasmb: What are your feelings now?

key: yes 0
decomp: *
reasmb: You seem to be quite positive.
reasmb: You are sure.
reasmb: I see.
reasmb: I understand.

key: no 0
decomp: * no one *
goto: everyone
decomp: *
reasmb: Are you saying no just to be negative?
reasmb: You are being a bit negative.
reasmb: Why not?
reasmb: Why 'no'?

key: my 2
decomp: $ * my *
reasmb: Let's discuss further why your (2).
reasmb: Earlier you said your (2).
reasmb: But your (2).
reasmb: Does that have anything to do with the fact that your (2)?
decomp: * my * @family *
reasmb: Tell me more about your family.
reasmb: Who else in your family (4)?
reasmb: Your (3)?
reasmb: What else comes to mind when you think of your (3)?
decomp: * my *
reasmb: Your (2)?
reasmb: Why do you say your (2)?
reasmb: Does that suggest anything else which belongs to you?
reasmb: Is it important to you that your (2)?

key: can 0
decomp: * can you *
reasmb: You believe I can (2), don't you?
reasmb: You want me to be able to (2).
reasmb: Perhaps you would like to be able to (2) yourself.
decomp: * can i *
reasmb: Whether or not you can (2) depends on you more than on me.
reasmb: Do you want to be able to (2)?
reasmb: Perhaps you don't want to (2).
decomp: *
goto: xnone

key: what|how|when|where|why 0
decomp: *
reasmb: Why do you ask?
reasmb: Does that question interest you?
reasmb: What is it you really want to know?
reasmb: Are such questions much on your mind?
reasmb: What answer would please you most?
reasmb: What do you think?
reasmb: What comes to mind when you ask that?
reasmb: Have you asked such questions before?
reasmb: Have you asked anyone else?

key: because 0
decomp: *
reasmb: Is that the real reason?
reasmb: Don't any other reasons come to mind?
reasmb: Does that reason seem to explain anything else?
reasmb: What other reasons might there be?

key: hello|hi 0
decomp: *
reasmb: How do you do. Please state your problem.
reasmb: Hi. What seems to be your problem?

key: alike 10
decomp: *
reasmb: In what way?
reasmb: What resemblance do you see?
reasmb: What does that similarity suggest to you?
reasmb: What other connections do you see?
reasmb: What do you suppose that resemblance means?
reasmb: Could there really be some connection?
reasmb: How?

key: like 10
decomp: * @be * like *
goto: alike
decomp: *
goto: xnone

key: everyone|everybody|nobody|noone 2
decomp: * @everyone *
reasmb: Really, (2)?
reasmb: Surely not (2).
reasmb: Can you think of anyone in particular?
reasmb: Who, for example?
reasmb: Are you thinking of a very special person?
reasmb: You have a particular person in mind, don't you?

key: always 1
decomp: *
reasmb: Can you think of a specific example?
reasmb: When?
reasmb: What incident are you thinking of?
reasmb: Really, always?

key: mother|mom|father|dad|sister|brother|wife|husband|children|child|son|daughter 3
decomp: *
reasmb: Tell me more about your family.
reasmb: How do you get along with your family?
reasmb: Is your family important to you?
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn long_input_is_answered_quickly() {
        let start = std::time::Instant::now();
        super::Conversation::new().reply(&"you ".repeat(250_000));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    use super::*;

    #[test]
    fn script_loads() {
        assert_eq!(SCRIPT.keys.len(), 28);
    }

    #[test]
    fn replies() {
        let cases = [
            ("I am sad", "I am sorry to hear that you are sad."),
            ("I need a holiday", "What would it mean to you if you got a holiday?"),
            ("I remember my first computer", "Do computers worry you?"),
            ("I remember the sea", "Do you often think of the sea?"),
            ("you are a machine", "Do computers worry you?"),
            ("you are kind", "What makes you think I am kind?"),
            ("my mother hates me", "Tell me more about your family."),
            ("Why is the sky blue?", "Why do you ask?"),
            ("sorry!", "Please don't apologise."),
            ("I feel tired", "Tell me more about such feelings."),
            ("I dreamt of trains", "Really, of trains?"),
            ("everybody laughs at me", "Really, everybody?"),
            ("xyzzy", "I'm not sure I understand you fully."),
            ("", "Please say something."),
            ("ok goodbye", "Goodbye. Thank you for talking to me."),
        ];
        for (input, want) in cases {
            assert_eq!(Conversation::new().reply(input), want, "input {input:?}");
        }
    }

    #[test]
    fn reflects_pronouns() {
        assert_eq!(Conversation::new().reply("you hate me"), "Why do you think I hate you?");
        assert_eq!(Conversation::new().reply("can you help me"), "You believe I can help you, don't you?");
    }

    #[test]
    fn rotates_reassemblies() {
        let mut c = Conversation::new();
        let a = c.reply("xyzzy");
        let b = c.reply("xyzzy");
        assert_ne!(a, b);
    }

    #[test]
    fn remembers_and_recalls() {
        let mut c = Conversation::new();
        c.reply("my cat is ill");
        // Nothing matches; the memorized line comes back.
        assert_eq!(c.reply("xyzzy"), "Let's discuss further why your cat is ill.");
    }
}
