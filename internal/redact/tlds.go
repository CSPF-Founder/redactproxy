// A curated TLD list (gTLDs + ccTLDs).
//
// Used as a validation gate on top of golang.org/x/net/publicsuffix, not as
// the primary domain splitter: the public suffix spec deliberately treats any
// UNRECOGNIZED final label as an implicit valid suffix --
// EffectiveTLDPlusOne("console.log") succeeds with suffix "log", icann=false,
// no error -- indistinguishable by return value alone from a real listed
// private suffix like "github.io". PSL still does the actual splitting
// (needed for correct multi-label suffixes like "co.uk" and "github.io");
// this list only vetoes candidates whose suffix's last label isn't a real,
// deployed TLD, closing the "console.log", "scan_results_1.5.txt" class of
// false positive that PSL alone lets through.
package redact

var knownTLDs = map[string]bool{
	// These 8 are all real, currently-delegated gTLDs that don't appear
	// in the alphabetical block below.
	"biz": true, "travel": true, "jobs": true, "coop": true, "aero": true,
	"museum": true, "store": true, "studio": true,

	// "local" and "internal" are NOT real, ICANN-delegated gTLDs; they're
	// special-use reserved names (RFC 6762 for .local's mDNS use, RFC 9476
	// for .internal, both reserved specifically so they NEVER resolve on
	// the public internet). Included here anyway, deliberately: an
	// internal Active Directory / service-discovery domain (e.g.
	// "noreply@corp.local") is exactly the kind of sensitive
	// internal-infrastructure naming this tool exists to protect, even
	// though it could never be a real internet target. This list's job
	// for this tool is "is this domain-shaped text worth protecting", not
	// "is this an ICANN-delegated TLD": the two questions usually have
	// the same answer, but not here.
	"local": true, "internal": true,

	"ac": true, "academy": true, "accountant": true, "accountants": true, "actor": true,
	"ad": true, "adult": true, "ae": true, "af": true, "africa": true, "ag": true,
	"agency": true, "ai": true, "airforce": true, "al": true, "am": true, "an": true, "ao": true,
	"apartments": true, "app": true, "aq": true, "ar": true, "archi": true, "army": true,
	"art": true, "as": true, "asia": true, "associates": true, "at": true, "attorney": true,
	"au": true, "auction": true, "audio": true, "auto": true, "autos": true, "aw": true,
	"ax": true, "az": true, "ba": true, "baby": true, "band": true, "bar": true,
	"bargains": true, "bb": true, "bd": true, "be": true, "beer": true, "berlin": true,
	"best": true, "bet": true, "bf": true, "bg": true, "bh": true, "bi": true, "bid": true,
	"bike": true, "bio": true, "bj": true, "black": true, "blackfriday": true, "blog": true,
	"blue": true, "bm": true, "bn": true, "bo": true, "boats": true, "bond": true, "boo": true,
	"boston": true, "bot": true, "boutique": true, "br": true, "bs": true, "bt": true,
	"build": true, "builders": true, "business": true, "buzz": true, "bv": true, "bw": true,
	"by": true, "bz": true, "ca": true, "cab": true, "cafe": true, "cam": true, "camera": true,
	"camp": true, "capital": true, "car": true, "cards": true, "care": true, "careers": true,
	"cars": true, "casa": true, "cash": true, "casino": true, "catering": true, "cc": true,
	"cd": true, "center": true, "ceo": true, "cf": true, "cfd": true, "cg": true, "ch": true,
	"charity": true, "chat": true, "cheap": true, "christmas": true, "church": true, "ci": true,
	"city": true, "ck": true, "cl": true, "claims": true, "cleaning": true, "click": true,
	"clinic": true, "clothing": true, "cloud": true, "club": true, "cm": true, "cn": true,
	"co": true, "codes": true, "coffee": true, "college": true, "com": true, "community": true,
	"company": true, "computer": true, "condos": true, "construction": true, "consulting": true,
	"contact": true, "contractors": true, "cooking": true, "cool": true, "coupons": true,
	"courses": true, "cr": true, "credit": true, "creditcard": true, "cricket": true,
	"cruises": true, "cu": true, "cv": true, "cw": true, "cx": true, "cy": true, "cyou": true,
	"cz": true, "dad": true, "dance": true, "date": true, "dating": true, "day": true,
	"de": true, "degree": true, "delivery": true, "democrat": true, "dental": true,
	"dentist": true, "desi": true, "design": true, "dev": true, "diamonds": true, "diet": true,
	"digital": true, "direct": true, "directory": true, "discount": true, "dj": true, "dk": true,
	"dm": true, "do": true, "doctor": true, "dog": true, "domains": true, "download": true,
	"dz": true, "earth": true, "ec": true, "eco": true, "edu": true, "education": true,
	"ee": true, "eg": true, "email": true, "energy": true, "engineer": true, "engineering": true,
	"enterprises": true, "equipment": true, "er": true, "es": true, "esq": true, "estate": true,
	"et": true, "eu": true, "events": true, "exchange": true, "expert": true, "exposed": true,
	"express": true, "fail": true, "faith": true, "family": true, "fans": true, "farm": true,
	"fashion": true, "feedback": true, "fi": true, "film": true, "finance": true,
	"financial": true, "fish": true, "fishing": true, "fit": true, "fitness": true, "fj": true,
	"fk": true, "flights": true, "florist": true, "flowers": true, "fm": true, "fo": true,
	"football": true, "forsale": true, "foundation": true, "fr": true, "fun": true, "fund": true,
	"furniture": true, "futbol": true, "fyi": true, "ga": true, "gallery": true, "game": true,
	"games": true, "garden": true, "gay": true, "gb": true, "gd": true, "gdn": true, "ge": true,
	"gf": true, "gg": true, "gh": true, "gi": true, "gifts": true, "gives": true, "giving": true,
	"gl": true, "glass": true, "global": true, "gm": true, "gmbh": true, "gn": true,
	"gold": true, "golf": true, "gov": true, "gp": true, "gq": true, "gr": true,
	"graphics": true, "gratis": true, "green": true, "gripe": true, "group": true, "gs": true,
	"gt": true, "gu": true, "guide": true, "guitars": true, "guru": true, "gw": true, "gy": true,
	"hair": true, "hamburg": true, "haus": true, "health": true, "healthcare": true,
	"help": true, "hiphop": true, "hk": true, "hm": true, "hn": true, "hockey": true,
	"holdings": true, "holiday": true, "homes": true, "horse": true, "hospital": true,
	"host": true, "hosting": true, "house": true, "how": true, "hr": true, "ht": true,
	"hu": true, "icu": true, "id": true, "ie": true, "il": true, "im": true, "in": true,
	"info": true, "ink": true, "institute": true, "insure": true, "int": true,
	"international": true, "investments": true, "io": true, "iq": true, "ir": true,
	"irish": true, "is": true, "it": true, "je": true, "jetzt": true, "jewelry": true,
	"jm": true, "jo": true, "jp": true, "juegos": true, "kaufen": true, "ke": true, "kg": true,
	"kh": true, "ki": true, "kids": true, "kitchen": true, "kiwi": true, "km": true, "kn": true,
	"kp": true, "kr": true, "krd": true, "kw": true, "ky": true, "kyoto": true, "kz": true,
	"la": true, "land": true, "lat": true, "law": true, "lawyer": true, "lb": true, "lc": true,
	"lease": true, "legal": true, "lgbt": true, "li": true, "life": true, "lighting": true,
	"limited": true, "limo": true, "link": true, "live": true, "lk": true, "loan": true,
	"loans": true, "lol": true, "london": true, "love": true, "lr": true, "ls": true, "lt": true,
	"ltd": true, "ltda": true, "lu": true, "luxury": true, "lv": true, "ly": true, "ma": true,
	"maison": true, "management": true, "market": true, "marketing": true, "markets": true,
	"mba": true, "mc": true, "md": true, "me": true, "media": true, "melbourne": true,
	"meme": true, "memorial": true, "men": true, "mg": true, "mh": true, "miami": true,
	"mil": true, "mk": true, "ml": true, "mm": true, "mn": true, "mo": true, "mobi": true,
	"moda": true, "moe": true, "mom": true, "money": true, "monster": true, "mortgage": true,
	"motorcycles": true, "mov": true, "movie": true, "mp": true, "mq": true, "mr": true,
	"ms": true, "mt": true, "mu": true, "mv": true, "mw": true, "mx": true, "my": true,
	"mz": true, "na": true, "nagoya": true, "navy": true, "nc": true, "ne": true,
	// ".name" deliberately excluded, same reasoning as ".properties"
	// below: it collides with common CSS class selectors (e.g. Tomcat's
	// own default error-page CSS, "A.name { color: black; }"), which is a
	// far more common real-world occurrence than the ".name" gTLD
	// (marketed for personal-name domains, minimal real adoption).
	// ".new" deliberately excluded despite being a real, currently-
	// delegated gTLD: Ruby's `.new` constructor-call syntax (e.g.
	// "Mutex.new", "OptString.new", common in tool console/log output,
	// Metasploit's msfconsole included) would otherwise get wrongly
	// tokenized as a domain on every occurrence. Real-world adoption of
	// the actual ".new" gTLD is negligible by comparison. Same call as
	// ".properties"/".name" above, same reasoning.
	"net": true, "network": true, "news": true, "nf": true, "ng": true, "ngo": true,
	"ni": true, "ninja": true, "nl": true, "no": true, "now": true, "np": true, "nr": true,
	"nu": true, "nyc": true, "nz": true, "observer": true, "okinawa": true, "om": true,
	"one": true, "ong": true, "onl": true, "online": true, "org": true, "organic": true,
	"osaka": true, "pa": true, "page": true, "paris": true, "partners": true, "parts": true,
	"party": true, "pe": true, "pet": true, "pf": true, "pg": true, "ph": true, "phd": true,
	"photo": true, "photography": true, "photos": true, "pics": true, "pictures": true,
	"pink": true, "pizza": true, "pk": true, "pl": true, "place": true, "plumbing": true,
	"plus": true, "pm": true, "pn": true, "poker": true, "porn": true, "pr": true, "press": true,
	"pro": true, "productions": true, "prof": true, "promo": true,
	// ".properties" deliberately excluded despite being a real,
	// currently-delegated gTLD: "config.properties" (Java's own,
	// extremely common config-file naming convention) would otherwise get
	// its "config" label needlessly tokenized on every mention.
	// Real-world adoption of the actual ".properties" gTLD is close to
	// nonexistent; ".properties" FILES are one of the most common
	// artifacts in any Java-heavy engagement. This
	// is the opposite call from the ccTLD-collision cases (.md/.io/.co
	// etc, kept in) and the .local/.internal case above (kept in): there
	// the real-target risk of excluding was judged too high; here the
	// false-positive frequency was judged too high to keep it in. Same
	// tradeoff axis, different weighing, both deliberate.
	"property": true, "protection": true, "ps": true, "pt": true, "pub": true, "pw": true,
	"py": true, "qa": true, "quest": true, "racing": true, "re": true, "recipes": true,
	"red": true, "rehab": true, "reise": true, "reisen": true, "rent": true, "rentals": true,
	"repair": true, "report": true, "republican": true, "rest": true, "restaurant": true,
	"review": true, "reviews": true, "rip": true, "ro": true, "rocks": true, "rodeo": true,
	"rs": true, "rsvp": true, "ru": true, "run": true, "rw": true, "sa": true, "saarland": true,
	"sale": true, "salon": true, "sarl": true, "sb": true, "sbs": true, "sc": true,
	"school": true, "schule": true, "science": true, "sd": true, "se": true, "services": true,
	"sex": true, "sexy": true, "sg": true, "sh": true, "shoes": true, "shop": true,
	"shopping": true, "show": true, "si": true, "singles": true, "site": true, "sj": true,
	"sk": true, "skin": true, "sl": true, "sm": true, "sn": true, "so": true, "soccer": true,
	"social": true, "software": true, "solar": true, "solutions": true, "soy": true,
	"space": true, "spiegel": true, "sr": true, "st": true, "study": true, "style": true,
	"su": true, "sucks": true, "supply": true, "support": true, "surf": true, "surgery": true,
	"sv": true, "sx": true, "sy": true, "systems": true, "sz": true, "tax": true, "taxi": true,
	"tc": true, "td": true, "team": true, "tech": true, "technology": true, "tel": true,
	"tf": true, "tg": true, "th": true, "theater": true, "tips": true, "tires": true, "tj": true,
	"tk": true, "tl": true, "tm": true, "tn": true, "to": true, "today": true, "tools": true,
	"top": true, "tours": true, "town": true, "toys": true, "tp": true, "tr": true,
	"trade": true, "training": true, "tt": true, "tube": true, "tv": true, "tw": true,
	"tz": true, "ua": true, "ug": true, "uk": true, "university": true, "uno": true, "us": true,
	"uy": true, "uz": true, "va": true, "vacations": true, "vc": true, "ve": true,
	"ventures": true, "vet": true, "vg": true, "vi": true, "video": true, "villas": true,
	"vin": true, "vip": true, "vision": true, "vlaanderen": true, "vn": true, "vodka": true,
	"vote": true, "voting": true, "voyage": true, "vu": true, "wales": true, "wang": true,
	"watch": true, "webcam": true, "website": true, "wedding": true, "wf": true, "wiki": true,
	"wine": true, "work": true, "works": true, "world": true, "ws": true, "wtf": true,
	"xxx": true, "xyz": true, "ye": true, "yoga": true, "yokohama": true, "you": true,
	"yt": true, "za": true, "zm": true, "zone": true, "zw": true,
}
