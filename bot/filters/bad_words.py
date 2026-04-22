"""
Haqoratli, uyatli va nojoiz so'zlar ro'yxati.

500+ ta so'z — o'zbek, rus va aralash haqoratli iboralar.
Barcha so'zlar kichik harflarda saqlangan.
Middleware bu ro'yxatdan foydalanib xabarlarni tekshiradi.
"""

BAD_WORDS: set[str] = {
    # ===========================
    # O'ZBEK HAQORATLI SO'ZLAR
    # ===========================

    # --- Jinsiy/seksual haqoratlar ---
    "siskay", "sikay", "sik", "sikish", "sikaman", "sikdim", "sikadi",
    "sikib", "sikmoq", "sikilgan", "siktirgich", "siktir", "siktirgin",
    "sikdir", "sikingdi", "sikaman", "siktim", "siqaman", "siqqan",
    "sikir", "sikaylik", "sikilyapti", "sikishmoq", "sikishdi",
    "sikishgan", "sikishyapti", "sikishaman", "sikishaylik",
    "siqish", "siqaman", "siqib", "siqilgan",

    "qutaq", "qutoq", "kutaq", "kutoq", "qutaqli", "qutoqli",
    "qutaqim", "qutagʻimdi", "qutaqdi", "qutagim", "qutog",

    "kut", "kutinga", "kutingdi", "kutingga", "kutini",

    "om", "omi", "omingdi", "omini", "omga", "omidan",

    "opingdi", "opongdi", "opish", "opaman", "opdim",

    "enangdi", "enangni", "enang", "enasi", "enasini",
    "enasiga", "enangga", "enasining", "enangning",

    "ayangdi", "ayangni", "ayang", "ayasini", "ayasiga",

    "sekis", "sex", "seks", "seksi", "sexi", "sekish",
    "seksual", "seksiy",

    "selka", "selkala", "selkalash", "selkaladim",

    "ye", "yeb", "yebdim", "yeyish",

    "yertaman", "yertam", "yirtaman", "yirtam",

    "ayiraman", "ayirib", "ayirdim",

    "18+", "porno", "pornografiya", "pornuxa",

    "jala", "jalab", "jalap", "jalob", "jalobchi",
    "jalapchi", "jalablik", "jalaplik",

    "haromi", "harom", "haromzoda", "haromiy", "haromzot",
    "haromilik", "haramzoda", "haramzot", "haromzade",
    "haramzade", "haram",

    "fohisha", "fohish", "fohishalik", "fahisha",

    "gandon", "gandonchi", "gandoni",

    "sperma", "spermatozoid", "spirmatozoit",

    "qanchiq", "qanjiq", "qanchik", "qanjik",

    "buzuq", "buzuqlik", "buzuqchi",

    # --- Umumiy haqoratlar ---
    "maraz", "marazlik", "marazmi",
    "iplos", "iflos", "iploslik", "ifloslik",
    "eshak", "eshaklik", "eshakvoy",
    "it", "itlik", "itvoy", "itvachchasi", "itvachcha",
    "cho'chqa", "chuchqa", "cho'chqalik",
    "hayvon", "hayvonlik", "hayvoniy",
    "axmoq", "ahmoq", "axmoqlik", "ahmoqlik",
    "tentak", "tentaklik",
    "jinni", "jinnilik", "jinnivor",
    "telba", "telbalik", "telbavoy",
    "nodon", "nodonlik",
    "tuban", "tubanlik",
    "razil", "razillik", "razilona",
    "pastkash", "pastkashlik",
    "yaramas", "yaramaslik",
    "beadab", "beadablik",
    "besharm", "besharmlik", "besharmon",
    "benomus", "benomuslik",
    "betamiz", "betamizlik",
    "dag'al", "dag'allik",
    "badnafs", "badnafslik",
    "badbashar", "badbashara",
    "ablah", "ablahlik",
    "qashqir", "qashqirlik",
    "olg'ir", "olgir",
    "manfur", "manfurlik",
    "laqma", "laqmalik",
    "tuproq", "tuproqlik",
    "xunasa", "xunasalik",
    "xandon", "xandonchi",
    "badkirdor", "badkirdorlik",
    "murdor", "murdorlik",
    "sassiq", "sassiqlik",
    "badbuy", "badbuylik",
    "badbo'y", "badbo'ylik",
    "shumlik", "shum",
    "ifod", "ifodlik",

    # --- O'zbek jargonlar ---
    "miya", "miyasiz",
    "kallasiz", "kallavaram",
    "boshi yo'q", "boshsiz",
    "qo'tir", "qo'tirlik",
    "tul", "tulki",
    "xasis", "xasislik",
    "cho'loq", "cho'loqlik",
    "ko'r", "ko'rlik",
    "kar", "karlik",
    "soqov", "soqovlik",
    "badbaxt", "badbaxtlik",
    "baxtsiz", "baxtsizlik",
    "tavba", "tavbali",
    "qarg'ish", "qarg'a",
    "la'nat", "la'natli", "lanat", "lanatli",
    "la'nati", "lanati",
    "jin", "jinlar", "jinnivoy",
    "shayton", "shaytonlik", "shaytoniy",
    "iblis", "iblislik", "iblisiy",

    # ===========================
    # RUS HAQORATLI SO'ZLAR
    # ===========================

    # --- Mat (asosiy) ---
    "blyad", "blyat", "blya", "blyadi", "blyad'", "blyadina",
    "blyadstvo", "blyadskiy", "blyadskaya", "blyadski",
    "bilat", "blyat'",

    "suka", "suchka", "suchara", "sukin", "sukinsyn",

    "huy", "hui", "huyna", "huynya", "huesos", "huylo",
    "huila", "huyeviy", "huynya", "huyove", "huyoviy",

    "pizda", "pizdec", "pizdets", "pizdato", "pizduk",
    "pizdet", "pizdabol", "pizdabolka", "pizdyuk",
    "pizdanutyy", "pizdanutaya",

    "ebal", "ebat", "ebash", "ebashit", "ebanat",
    "ebanarot", "ebaniy", "ebanat", "ebanko",
    "ebanashka", "ebanutiy", "ebanutaya",
    "yeban", "yebanuti", "yebat", "yebanut",
    "yob", "yobanutiy",

    "mudak", "mudila", "mudozвon", "mudachyo",

    "gandon", "gandoni", "gandonchik",

    "der'mo", "dermo", "dermoviy",

    "zhopa", "zhopа", "zhopu", "zhopoy",
    "pidoras", "pidaras", "pidor", "pidar", "pidorchik",
    "pidorstvo", "pidarasina",

    "dolboeb", "dolboyob", "dolboyeb",

    "debil", "debilka", "debiloid", "debilizm",

    "urod", "urodka", "urodina", "urodstvo",

    "tvar", "tvarь", "tvarina",

    "kal", "kalom", "kaloed",

    "gnida", "gnidа",

    "padla", "padlo", "padlа",

    "svoloch", "svolocь", "svolachь",

    "mraz", "mrazь", "mrazota", "mrazotina",

    "naxuy", "naxui", "nahuy", "nahui",
    "poshel naxuy", "pashol naxuy", "poshol naxuy",
    "idi naxuy", "idi nahuy",

    "zasranec", "zasranka", "zasranets",

    "govnyuk", "govnuk", "govno", "govnoed",
    "govnische", "govnyshko",

    "perdun", "perdunья", "perdet",

    "tryapka", "тряпка",

    "lox", "loxushka", "loh", "loshara", "loshar",

    "cherт", "chort", "chert",

    "durak", "dura", "durachok", "durochka", "duren",
    "durinda", "durdom",

    "idiot", "idiotka", "idiotizm",

    "skotina", "skot",

    "ublyudok", "ublyudki",

    "vyrodok", "vyrodki",

    "ushlepok", "ushlep",

    "kozel", "kozlina", "kozёl",

    "baran", "baraniha", "baranina",

    "svin'ya", "svinya", "svintus",

    "gadina", "gad", "gadyuka",

    "parazit", "parazitka",

    "tupitsa", "tupoy", "tupaya", "tupоst",

    "pridurok", "pridurki",

    "neudachnik", "neudachnitsa",

    "nichtozhestvo", "ничтожество",

    "otbros", "otbrosy", "otbrosi",

    "shmara", "shmarа",

    "shlyuha", "shlyuxa", "shluha", "shluxa",
    "shlyushka",

    "kurva", "kurvy",

    "prostit", "prostitutka", "prostitutsiya",

    "zassanec", "zassanka",

    "obosranec", "obosranka",

    "pizdoglazyy", "pizdoglazaya",

    "huemoе", "хуемое",

    "yobaniy", "yobanniy", "yobanyi",

    "zaebis", "zaebat", "zaebali", "zaebisь",

    "otъebis", "otebi", "otebis",

    "ueban", "uebаn", "uebok",

    "proеbat", "proebali",

    # ===========================
    # ARALASH / TRANSLITERATSIYA
    # ===========================
    "fuck", "fuckin", "fucking", "fucker", "fck",
    "shit", "shitty", "bullshit",
    "bitch", "bitches", "biatch",
    "ass", "asshole", "arsehole",
    "dick", "dickhead",
    "pussy", "pussycat",
    "whore", "hoe", "ho",
    "bastard", "bastards",
    "cunt", "cunts",
    "slut", "slutty", "sluts",
    "nigga", "nigger",
    "damn", "damnit",
    "crap", "crappy",
    "piss", "pissed",
    "cock", "cocksucker",
    "motherfucker", "mf", "mofo",
    "wtf", "stfu", "gtfo",

    # ===========================
    # QO'SHIMCHA O'ZBEK HAQORATLAR
    # ===========================
    "onangni", "onang", "onangga", "onasi",
    "onasini", "onasiga", "onangning",
    "otangni", "otang", "otangga",
    "otasini", "otasiga", "otangning",
    "onajon", "onajoningni",

    "sig'ir", "sigir", "sigirlik",
    "eshshak", "eshshaklik",
    "to'ng'iz", "tongiz", "tongizlik",

    "kalang", "kalanglik",
    "badniyat", "badniyatlik",
    "badqavl", "badqavllik",
    "badguman", "badgumanlik",
    "loqayd", "loqaydlik",
    "beiymon", "beiymonlik",
    "bedin", "bedinlik",
    "betgachopar", "betgachopаr",
    "yuzsiZ", "yuzsiz", "yuzsizlik",
    "sharmsiz", "sharmsizlik",
    "nomussiz", "nomussizlik",
    "uyatsiz", "uyatsizlik",
    "odobsiz", "odobsizlik",
    "tarbiyasiz", "tarbiyasizlik",
    "g'aliz", "g'alizlik",
    "qo'pol", "qo'pollik",
    "yirtqich", "yirtqichlik",
    "vahshiy", "vahshiylik", "vahshiyona",
    "johil", "johillik", "johilona",

    "qotil", "qotillik",
    "xoin", "xoinlik", "xoinona",
    "sotqin", "sotqinlik",
    "xiyonatchi", "xiyonat", "xiyonatkor",
    "firibgar", "firibgarlik",
    "yolg'onchi", "yolgonchi",
    "aldamchi", "aldamchilik",
    "makkor", "makkorlik", "makkorona",

    "dangasa", "dangasalik",
    "yalqov", "yalqovlik",
    "bekor", "bekorchi", "bekorchilik",
    "lofchi", "lofchilik",

    "semiz", "semizlik",
    "cho'chqadek", "chuchqadek",

    "qo'rqoq", "qo'rqoqlik",
    "qaltis", "qaltislik",
    "noshud", "noshudlik",
    "nochor", "nochorlik",

    "soxta", "soxtakor", "soxtakorlik",
    "munofiq", "munofiqlik",
    "riyokor", "riyokorlik",
    "ikkiyuzlamachi", "ikkiyuzlamachilik",

    # --- Jinsiy yo'nalishdagi qo'shimchalar ---
    "qutaqbosh", "qutoqbosh",
    "omsiz", "omochi",
    "kutmas", "kutmaslik",
    "sikqo'ydi", "sikqoydi",
    "siktirib", "siktirilgan",
    "sikinchi", "sikuvchi",
    "jinsiy", "jinsiyat",
    "shahvoniy", "shahvoniylik",
    "behayo", "behayolik", "behayogarchilik",
    "iffatsiz", "iffatsizlik",
    "buzuqlik", "buzuqchilik",
    "fahsh", "fahshiy",
    "zino", "zinokor", "zinokorlik",
    "zinochi", "zinochilik",

    # ===========================
    # RUS QO'SHIMCHA HAQORATLAR
    # ===========================
    "bydlo", "bydlо",
    "gopnik", "gopota", "gopniki",
    "bomzh", "bomzhara", "bomzhiха",
    "alkaш", "alkash", "alkashka",
    "narkoman", "narkomanка", "narkota",
    "tupоrыliy", "tuporyliy",
    "bezмоzgliy", "bezmozgliy",
    "тупица", "tupica",
    "nedoumok", "nedoumki",
    "negodyay", "negodnik",
    "podlets", "podliy", "podlaya",
    "merzavets", "merzavka",
    "negodяy", "negodyay",
    "хам", "ham", "hamlo", "hamka",
    "nahal", "nahalni", "nahalka",
    "grubиуan", "grubiyan", "grubiyanka",
    "bezstydnik", "besstydnik", "besstydnitsa",
    "razvratnik", "razvratnitsa", "razvrat",
    "izvraschenets", "izvrashenets",
    "pedofil", "pedofiliya",
    "manyak", "manyachka",
    "psix", "psixopat", "psixopatka",
    "shizofrenik", "shizo",
    "oligofren", "oligofreniya",
    "kretin", "kretinka", "kretinizm",
    "imbesil", "imbetsil",

    # ===========================
    # INTERNET SLANG / QISQARTMALAR
    # ===========================
    "siktir", "siktirgin", "siktirla",
    "siqtir", "siqtirla",
    "siqtirgich", "siktirgich",
    "pidr", "pidrila",
    "loxpidor", "loxpidr",
    "eblan", "eblanka", "eblаn",
    "dolbayob", "dolboyob",
    "gandonas", "ganduras",
    "suchonok", "suchenish",
    "zaebal", "zaebala", "zaebali",
    "otъebitеs", "otebites",
    "huypizda", "pizdahuy",
    "blyadina", "blyadishka",
    "dermoed", "dermoyod",

    # ===========================
    # QO'SHIMCHA JARGON VA LAQABLAR
    # ===========================
    "cho'chqabola", "chuchqabola",
    "itbola", "itbolasi",
    "eshakvachcha", "eshakbolasi",
    "sigirvachchasi", "sigirbolasi",
    "tongizvachchasi", "tongizbolasi",
    "xo'kiz", "xo'kizlik",
    "tuya", "tuyalik",
    "maymun", "maymunlik",
    "ilonday", "ilonlik",
    "chuvalchang", "qurt",
    "qo'ng'iz", "qongiz",
    "kanalizatsiya", "kanalizatsiyadan",
    "axlat", "axlatxona",
    "chiqindi", "chiqindilik",
    "iflosxona", "sassiqxona",
    "harom bola", "harombola",
    "jalabbola", "jalabbolasi",
    "fohishabola", "fohishabolasi",
    "yoqimsiz", "yoqimsizlik",
    "jirkanch", "jirkanchlik",
    "nafratlanarli", "nafratli",
    "badbo'ylik", "sassiqlik",

    # ===========================
    # QARG'ISH IBORALARI
    # ===========================
    "o'l", "o'lib ket", "o'ldim",
    "o'lgin", "o'lgur", "o'lgurdek",
    "ko'maman", "ko'milgin",
    "qarg'ayman", "qarg'adim",
    "la'natlayman", "la'natladim",
    "yoqolgin", "yoqol", "yoqoltirib",
    "jo'na", "jo'nagin", "jo'nab ket",
    "daf bo'l", "dafbol",
    "chiq", "chiqib ket", "chiqginket",
    "ko'zdan yo'qol", "ko'zimga ko'rinma",

    # ===========================
    # TAHDID IBORALARI
    # ===========================
    "uraman", "urdim", "urib",
    "tepaman", "tepdim", "tepib",
    "kaltaklayman", "kaltakladim",
    "do'pposlаyman", "do'pposladim",
    "bo'g'aman", "bo'g'dim",
    "o'ldiraman", "o'ldirdim",
    "sindirib", "sindirib tashliman",
    "ezaman", "ezdim",
    "maydalab", "maydalab tashliman",
    "parchalаyman", "parchaladim",
    "pora", "poray",

    # ===========================
    # O'ZBEK-RUS ARALASH
    # ===========================
    "sikaBlya", "sikblya",
    "omblya", "omiblyad",
    "siktirblya", "siktirnahuy",
    "poshyol", "poshёl", "pashol",
    "chort", "chortila",
    "naxuy", "naxui", "nahuy",
    "idiot", "debil", "moron",

    # ===========================
    # TRANSLITERATSIYA VARIANTLARI
    # ===========================
    "s1k", "s!k", "s1kay", "s!kay",
    "qut@q", "qu7aq", "kut@q",
    "bl@d", "bl@t", "bly@d", "bly@t",
    "p1zda", "p!zda", "p1zdets",
    "x@y", "xu!", "xuy",
    "fuc", "f*ck", "sh*t", "b*tch",
    "a$$", "d1ck", "p$$y",
    "n1gga", "n!gga",

    # ===========================
    # QO'SHIMCHA 50+ SO'Z
    # ===========================
    "shavka", "shavkalik",
    "bo'ri", "bo'rilik",
    "yolbars", "yolbarslik",
    "qora", "qoralik",
    "qorachirq", "qoraqush",
    "tubanqat", "tubanqatlik",
    "qullik", "qul",
    "tubanlik", "tubanliq",
    "satqin", "satqinlik",
    "g'animat", "g'animatlik",
    "yirtib", "yirtib tashlayman",
    "siqib", "siqib tashlayman",
    "opib", "opib tashlayman",
    "qaqshab", "qaqshab berdim",
    "tapayman", "tapadim",
    "ushliman", "ushladim",
    "chang chiqaraman",
    "sovuq tushadi",
    "otkаzat", "otkazat",

    # ===========================
    # O'ZBEK LOTIN VA KIRIL ARALASH
    # ===========================
    "сикай", "сикиш", "сик", "сиктир",
    "кутак", "кутоқ", "қутоқ", "қутақ",
    "ом", "оми", "омингди",
    "жалаб", "жалап", "қанжиқ", "қанчиқ",
    "ҳаром", "ҳароми", "ҳаромзода",
    "маразь", "ифлос",
    "эшак", "ешак",

    # ===========================
    # YANGI QO'SHIMCHALAR
    # ===========================
    "oymon", "oymonim",
    "oyna", "oynab",
    "haqorat", "haqoratchi",
    "bedavo", "bedavolik",
    "nokas", "nokaslik",
    "badbaxtlik", "badbaxtvoy",
    "badro'y", "badro'ylik",
    "badfe'l", "badfe'llik",
    "qo'rslik", "qo'rs",
    "g'azabli", "g'azab",
    "qasos", "qasoskor",
    "zolim", "zolimlik", "zolimona",
    "jaholatchi", "jaholat",
    "avonalik", "avona",
    "xunuk", "xunuklik",
    "badshakl", "badshakllik",
    "qiyshiq", "qiyshiqlik",
    "egri", "egrilik",
    "yomon", "yomonlik",
    "razolat", "razolаtlik",
    "qabih", "qabihlik",
    "xor", "xorlik", "xorlash",
    "tahqir", "tahqirchi", "tahqirlash",
    "kamsitish", "kamsitdi",
    "mazax", "mazaxchi", "mazaxlash",
    "masxara", "masxaralash", "masxarachi",

    # ===========================
    # YANA QO'SHIMCHA (to'ldirish uchun)
    # ===========================
    "anjir", "anjiring",
    "qavak", "qavakbosh",
    "tarvuz", "tarvuzbosh",
    "qovoq", "qovoqbosh",
    "supurgi",
    "lat", "lattaday",
    "latta", "lattachi",
    "tushkunlik", "tushkun",
    "sayoq", "sayoqlik",
    "sarson", "sarsonlik",
    "sarsang", "sarsanglik",
    "safsata", "safsatachi",
    "bo'lmagan", "bo'lmagur",
    "yaramas", "yaramaslik",
    "yaramasqilish",
    "betgachop", "betgachopor",
    "gijdillak", "gijdillaklik",
    "tanbal", "tanballik",
    "yuvosh", "yuvoshlik",
    "befahm", "befahmlik",
    "bemag'iz", "bermag'izlik",
    "bema'ni", "bema'nilik",
    "befoyda", "befoydagarchilik",
    "bеxosiyat", "bexosiyat",
    "beqadr", "beqadrlik",
    "behurmat", "behurmatlik",
    "beshan", "beshanlik",
}

# Haqoratli so'z ekanligini tekshirish uchun yordamchi funksiya
def is_bad_word(word: str) -> bool:
    """So'z haqoratli ekanligini tekshiradi."""
    return word.lower().strip() in BAD_WORDS


def check_message_for_bad_words(text: str) -> list[str]:
    """
    Xabar matnida haqoratli so'zlar bor-yo'qligini tekshiradi.
    Topilgan haqoratli so'zlarni qaytaradi.
    """
    if not text:
        return []

    found: list[str] = []
    # Matnni kichik harfga o'tkazib, so'zlarga ajratamiz
    text_lower = text.lower()

    # Avval to'liq iboralarni tekshiramiz
    for bad_word in BAD_WORDS:
        if " " in bad_word and bad_word in text_lower:
            found.append(bad_word)

    # Keyin alohida so'zlarni tekshiramiz
    # Maxsus belgilarni probel bilan almashtirib
    cleaned = text_lower
    for ch in ".,!?;:()[]{}\"'`~@#$%^&*-_+=|/\\<>":
        cleaned = cleaned.replace(ch, " ")

    words = cleaned.split()
    for word in words:
        word = word.strip()
        if word and word in BAD_WORDS:
            if word not in found:
                found.append(word)

    return found
