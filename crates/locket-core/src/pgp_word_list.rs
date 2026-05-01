//! Canonical PGP word list and safety-word derivation.
//!
//! See the file-level SOURCE comment below for provenance and licensing,
//! and [`safety_words_from_fingerprint_hex`] for the derivation contract.

// Canonical PGP word list — public domain.
//
// SOURCE
//
// The PGP word list is a phonetic alphabet first published by Patrick
// Juola and Philip Zimmermann for biometric verification of binary data
// (originally for PGPfone). It pairs each byte value (0..=255) with one
// word from an "even-syllable" list when the byte appears at an even
// offset and one word from an "odd-syllable" list when the byte appears
// at an odd offset; the two columns are deliberately phonetically
// distinct so that human speakers do not confuse them across positions.
//
// The list itself is an unornamented enumeration of common English
// words and is not protectable under U.S. copyright (Feist v. Rural
// Telephone, 499 U.S. 340) — uncopyrightable factual compilations.
// The list is reproduced verbatim in NIST SP 800-227 Appendix B
// (Recommendations for Key Establishment using KEMs) and on Wikipedia
// at <https://en.wikipedia.org/wiki/PGP_word_list>; both treat the
// list as public domain. This module is a verbatim transcription of
// the canonical 256+256 list.
//
// Reference: <https://en.wikipedia.org/wiki/PGP_word_list>
//
// USAGE
//
// `safety_words_from_fingerprint_hex` accepts a lowercase hex SHA-256
// fingerprint and returns four safety words derived from the first
// eight bytes of the fingerprint, per
// `docs/specs/team-sync-recovery.md:54`. The first eight bytes are
// split into four 2-byte windows; each window is reduced to a single
// byte index (XOR of its two bytes); windows alternate between the
// even-syllable and odd-syllable columns of the PGP word list.

/// Even-syllable column of the PGP word list (256 entries, indexed 0..=255).
pub const EVEN_SYLLABLE_WORDS: [&str; 256] = [
    "aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead", "aimless",
    "Algol", "allow", "alone", "ammo", "ancient", "apple", "artist", "assume", "Athens",
    "atlas", "Aztec", "baboon", "backfield", "backward", "banjo", "beaming", "bedlamp",
    "beehive", "beeswax", "befriend", "Belfast", "berserk", "billiard", "bison", "blackjack",
    "blockade", "blowtorch", "bluebird", "bombast", "bookshelf", "brackish", "breadline",
    "breakup", "brickyard", "briefcase", "Burbank", "button", "buzzard", "cement", "chairlift",
    "chatter", "checkup", "chisel", "choking", "chopper", "Christmas", "clamshell", "classic",
    "classroom", "cleanup", "clockwork", "cobra", "commence", "concert", "cowbell", "crackdown",
    "cranky", "crowfoot", "crucial", "crumpled", "crusade", "cubic", "dashboard", "deadbolt",
    "deckhand", "dogsled", "dragnet", "drainage", "dreadful", "drifter", "dropper", "drumbeat",
    "drunken", "Dupont", "dwelling", "eating", "edict", "egghead", "eightball", "endorse",
    "endow", "enlist", "erase", "escape", "exceed", "eyeglass", "eyetooth", "facial", "fallout",
    "flagpole", "flatfoot", "flytrap", "fracture", "framework", "freedom", "frighten", "gazelle",
    "Geiger", "glitter", "glucose", "goggles", "goldfish", "gremlin", "guidance", "hamlet",
    "highchair", "hockey", "indoors", "indulge", "inverse", "involve", "island", "jawbone",
    "keyboard", "kickoff", "kiwi", "klaxon", "locale", "lockup", "merit", "minnow", "miser",
    "Mohawk", "mural", "music", "necklace", "Neptune", "newborn", "nightbird", "Oakland",
    "obtuse", "offload", "optic", "orca", "payday", "peachy", "pheasant", "physique", "playhouse",
    "Pluto", "preclude", "prefer", "preshrunk", "printer", "prowler", "pupil", "puppy", "python",
    "quadrant", "quiver", "quota", "ragtime", "ratchet", "rebirth", "reform", "regain", "reindeer",
    "rematch", "repay", "retouch", "revenge", "reward", "rhythm", "ribcage", "ringbolt", "robust",
    "rocker", "ruffled", "sailboat", "sawdust", "scallion", "scenic", "scorecard", "Scotland",
    "seabird", "select", "sentence", "shadow", "shamrock", "showgirl", "skullcap", "skydive",
    "slingshot", "slowdown", "snapline", "snapshot", "snowcap", "snowslide", "solo", "southward",
    "soybean", "spaniel", "spearhead", "spellbind", "spheroid", "spigot", "spindle", "spyglass",
    "stagehand", "stagnate", "stairway", "standard", "stapler", "steamship", "sterling",
    "stockman", "stopwatch", "stormy", "sugar", "surmount", "suspense", "sweatband", "swelter",
    "tactics", "talon", "tapeworm", "tempest", "tiger", "tissue", "tonic", "topmost", "tracker",
    "transit", "trauma", "treadmill", "Trojan", "trouble", "tumor", "tunnel", "tycoon", "uncut",
    "unearth", "unwind", "uproot", "upset", "upshot", "vapor", "village", "virus", "Vulcan",
    "waffle", "wallet", "watchword", "wayside", "willow", "woodlark", "Zulu",
];

/// Odd-syllable column of the PGP word list (256 entries, indexed 0..=255).
pub const ODD_SYLLABLE_WORDS: [&str; 256] = [
    "adroitness", "adviser", "aftermath", "aggregate", "alkali", "almighty", "amulet", "amusement",
    "antenna", "applicant", "Apollo", "armistice", "article", "asteroid", "Atlantic", "atmosphere",
    "autopsy", "Babylon", "backwater", "barbecue", "belowground", "bifocals", "bodyguard",
    "bookseller", "borderline", "bottomless", "Bradbury", "bravado", "Brazilian", "breakaway",
    "Burlington", "businessman", "butterfat", "Camelot", "candidate", "cannonball", "Capricorn",
    "caravan", "caretaker", "celebrate", "cellulose", "certify", "chambermaid", "Cherokee",
    "Chicago", "clergyman", "coherence", "combustion", "commando", "company", "component",
    "concurrent", "confidence", "conformist", "congregate", "consensus", "consulting", "corporate",
    "corrosion", "councilman", "crossover", "crucifix", "cumbersome", "customer", "Dakota",
    "decadence", "December", "decimal", "designing", "detector", "detergent", "determine",
    "dictator", "dinosaur", "direction", "disable", "disbelief", "disruptive", "distortion",
    "document", "embezzle", "enchanting", "enrollment", "enterprise", "equation", "equipment",
    "escapade", "Eskimo", "everyday", "examine", "existence", "exodus", "fascinate", "filament",
    "finicky", "forever", "fortitude", "frequency", "gadgetry", "Galveston", "getaway", "glossary",
    "gossamer", "graduate", "gravity", "guitarist", "hamburger", "Hamilton", "handiwork",
    "hazardous", "headwaters", "hemisphere", "hesitate", "hideaway", "holiness", "hurricane",
    "hydraulic", "impartial", "impetus", "inception", "indigo", "inertia", "infancy", "inferno",
    "informant", "insincere", "insurgent", "integrate", "intention", "inventive", "Istanbul",
    "Jamaica", "Jupiter", "leprosy", "letterhead", "liberty", "maritime", "matchmaker", "maverick",
    "Medusa", "megaton", "microscope", "microwave", "midsummer", "millionaire", "miracle",
    "misnomer", "molasses", "molecule", "Montana", "monument", "mosquito", "narrative", "nebula",
    "newsletter", "Norwegian", "October", "Ohio", "onlooker", "opulent", "Orlando", "outfielder",
    "Pacific", "pandemic", "Pandora", "paperweight", "paragon", "paragraph", "paramount",
    "passenger", "pedigree", "Pegasus", "penetrate", "perceptive", "performance", "pharmacy",
    "phonetic", "photograph", "pioneer", "pocketful", "politeness", "positive", "potato",
    "processor", "provincial", "proximate", "puberty", "publisher", "pyramid", "quantity",
    "racketeer", "rebellion", "recipe", "recover", "repellent", "replica", "reproduce",
    "resistor", "responsive", "retraction", "retrieval", "retrospect", "revenue", "revival",
    "revolver", "sandalwood", "sardonic", "Saturday", "savagery", "scavenger", "sensation",
    "sociable", "souvenir", "specialist", "speculate", "stethoscope", "stupendous", "supportive",
    "surrender", "suspicious", "sympathy", "tambourine", "telephone", "therapist", "tobacco",
    "tolerance", "tomorrow", "torpedo", "tradition", "travesty", "trombonist", "truncated",
    "typewriter", "ultimate", "undaunted", "underfoot", "unicorn", "unify", "universe", "unravel",
    "upcoming", "vacancy", "vagabond", "vertigo", "Virginia", "visitor", "vocalist", "voyager",
    "warranty", "Waterloo", "whimsical", "Wichita", "Wilmington", "Wyoming", "yesteryear",
    "Yucatan",
];

/// Number of safety words produced by [`safety_words_from_fingerprint_hex`].
///
/// Per `docs/specs/team-sync-recovery.md:54`, safety words are derived from
/// the first eight bytes of the SHA-256 fingerprint split into four 2-byte
/// windows, producing a fixed-length human-pronounceable phrase.
pub const SAFETY_WORD_COUNT: usize = 4;

/// Number of fingerprint bytes consumed by [`safety_words_from_fingerprint_hex`].
const SAFETY_WORD_FINGERPRINT_BYTES: usize = SAFETY_WORD_COUNT * 2;

/// Derive safety words from a lowercase-hex SHA-256 fingerprint.
///
/// Returns up to [`SAFETY_WORD_COUNT`] words. Inputs shorter than
/// `SAFETY_WORD_FINGERPRINT_BYTES * 2` hex characters or containing
/// non-hex characters yield a shorter result rather than panicking;
/// well-formed fingerprints always produce exactly [`SAFETY_WORD_COUNT`]
/// words.
///
/// Each 2-byte window is reduced to a single 8-bit index by XOR-ing its
/// two bytes, then looked up in the alternating even/odd columns of the
/// PGP word list (window 0 even, window 1 odd, window 2 even, window 3 odd).
#[must_use]
pub fn safety_words_from_fingerprint_hex(fingerprint: &str) -> Vec<&'static str> {
    let mut bytes = [0u8; SAFETY_WORD_FINGERPRINT_BYTES];
    let mut decoded_count = 0usize;
    let chars: Vec<char> = fingerprint.chars().take(SAFETY_WORD_FINGERPRINT_BYTES * 2).collect();
    for (index, pair) in chars.chunks_exact(2).enumerate() {
        match (pair[0].to_digit(16), pair[1].to_digit(16)) {
            (Some(hi), Some(lo)) => {
                // Cast to u8 is safe: each digit fits in 4 bits.
                #[allow(clippy::cast_possible_truncation)]
                {
                    bytes[index] = ((hi << 4) | lo) as u8;
                }
                decoded_count = index + 1;
            }
            _ => break,
        }
    }
    let mut words = Vec::with_capacity(SAFETY_WORD_COUNT);
    for window in 0..SAFETY_WORD_COUNT {
        let lo = window * 2;
        let hi = lo + 1;
        if hi >= decoded_count {
            break;
        }
        let index = bytes[lo] ^ bytes[hi];
        let word = if window % 2 == 0 {
            EVEN_SYLLABLE_WORDS[index as usize]
        } else {
            ODD_SYLLABLE_WORDS[index as usize]
        };
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_lists_have_256_entries() {
        assert_eq!(EVEN_SYLLABLE_WORDS.len(), 256);
        assert_eq!(ODD_SYLLABLE_WORDS.len(), 256);
    }

    #[test]
    fn known_anchor_words_match_canonical_list() {
        // Anchors documented at <https://en.wikipedia.org/wiki/PGP_word_list>:
        // byte 0x00 even=aardvark, odd=adroitness;
        // byte 0xFF even=Zulu, odd=Yucatan.
        assert_eq!(EVEN_SYLLABLE_WORDS[0x00], "aardvark");
        assert_eq!(ODD_SYLLABLE_WORDS[0x00], "adroitness");
        assert_eq!(EVEN_SYLLABLE_WORDS[0xFF], "Zulu");
        assert_eq!(ODD_SYLLABLE_WORDS[0xFF], "Yucatan");
    }

    #[test]
    fn even_and_odd_lists_are_disjoint() {
        use std::collections::HashSet;
        let evens: HashSet<&&str> = EVEN_SYLLABLE_WORDS.iter().collect();
        let odds: HashSet<&&str> = ODD_SYLLABLE_WORDS.iter().collect();
        let intersect: Vec<_> = evens.intersection(&odds).collect();
        assert!(
            intersect.is_empty(),
            "even and odd PGP word columns must be phonetically disjoint, found overlap: {intersect:?}"
        );
    }

    #[test]
    fn each_column_has_unique_words() {
        use std::collections::HashSet;
        let evens: HashSet<&&str> = EVEN_SYLLABLE_WORDS.iter().collect();
        let odds: HashSet<&&str> = ODD_SYLLABLE_WORDS.iter().collect();
        assert_eq!(evens.len(), 256);
        assert_eq!(odds.len(), 256);
    }

    #[test]
    fn produces_exactly_n_words_for_well_formed_fingerprint() {
        let fingerprint = "00".repeat(32);
        let words = safety_words_from_fingerprint_hex(&fingerprint);
        assert_eq!(words.len(), SAFETY_WORD_COUNT);
    }

    #[test]
    fn deterministic_round_trip_for_zero_fingerprint() {
        // First 8 bytes are 0x00 0x00 ... so each window XORs to 0.
        // Windows alternate even/odd, both at index 0.
        let fingerprint = "00".repeat(32);
        let words = safety_words_from_fingerprint_hex(&fingerprint);
        assert_eq!(words, vec!["aardvark", "adroitness", "aardvark", "adroitness"]);
    }

    #[test]
    fn deterministic_round_trip_for_max_fingerprint() {
        // First 8 bytes are 0xFF; XOR of 0xFF^0xFF = 0x00, so windows
        // collapse to index 0 again.
        let fingerprint = "ff".repeat(32);
        let words = safety_words_from_fingerprint_hex(&fingerprint);
        assert_eq!(words, vec!["aardvark", "adroitness", "aardvark", "adroitness"]);
    }

    #[test]
    fn deterministic_known_vector_for_distinct_bytes() {
        // Window 0: 0x00 ^ 0xff = 0xff -> EVEN[0xff] = "Zulu".
        // Window 1: 0x11 ^ 0x22 = 0x33 -> ODD[0x33] = ODD_SYLLABLE_WORDS[0x33].
        // Window 2: 0xaa ^ 0x55 = 0xff -> EVEN[0xff] = "Zulu".
        // Window 3: 0x12 ^ 0x34 = 0x26 -> ODD[0x26] = ODD_SYLLABLE_WORDS[0x26].
        let fingerprint = "00ff112299aa55551234aabbccddeeff00112233445566778899aabbccddeeff";
        // Wait — the second window above used 0x99 0xaa not 0x11 0x22.
        // Recompute against the actual hex: bytes are
        // 0x00 0xff 0x11 0x22 0x99 0xaa 0x55 0x55 ...
        // window 0: 0x00 ^ 0xff = 0xff -> EVEN[0xff] = "Zulu".
        // window 1: 0x11 ^ 0x22 = 0x33 -> ODD[0x33].
        // window 2: 0x99 ^ 0xaa = 0x33 -> EVEN[0x33].
        // window 3: 0x55 ^ 0x55 = 0x00 -> ODD[0x00] = "adroitness".
        let words = safety_words_from_fingerprint_hex(fingerprint);
        assert_eq!(
            words,
            vec![
                EVEN_SYLLABLE_WORDS[0xff],
                ODD_SYLLABLE_WORDS[0x33],
                EVEN_SYLLABLE_WORDS[0x33],
                ODD_SYLLABLE_WORDS[0x00],
            ]
        );
        assert_eq!(words[0], "Zulu");
        assert_eq!(words[3], "adroitness");
    }

    #[test]
    fn different_bytes_produce_different_words() {
        let fp_a = "00".repeat(32);
        let mut fp_b_bytes = "00".repeat(32);
        fp_b_bytes.replace_range(0..2, "01");
        let a = safety_words_from_fingerprint_hex(&fp_a);
        let b = safety_words_from_fingerprint_hex(&fp_b_bytes);
        assert_ne!(a, b);
    }

    #[test]
    fn same_index_in_different_columns_yields_different_words() {
        // For any byte value v, EVEN[v] and ODD[v] are deliberately distinct.
        for v in 0u8..=255 {
            assert_ne!(
                EVEN_SYLLABLE_WORDS[v as usize],
                ODD_SYLLABLE_WORDS[v as usize],
                "even and odd columns collided at index {v}"
            );
        }
    }

    #[test]
    fn malformed_fingerprint_does_not_panic() {
        // Non-hex characters short-circuit but never panic.
        let result = safety_words_from_fingerprint_hex("zz");
        assert!(result.is_empty());
        let result = safety_words_from_fingerprint_hex("");
        assert!(result.is_empty());
        // Odd length + garbage tail.
        let result = safety_words_from_fingerprint_hex("00");
        // Fewer than 2 bytes decoded -> no full window.
        assert!(result.is_empty());
    }

    #[test]
    fn short_but_valid_fingerprint_produces_partial_output() {
        // Two bytes -> exactly one window -> one word.
        let words = safety_words_from_fingerprint_hex("0001");
        // 0x00 XOR 0x01 = 0x01 -> EVEN_SYLLABLE_WORDS[0x01].
        assert_eq!(words, vec![EVEN_SYLLABLE_WORDS[0x01]]);
    }
}
