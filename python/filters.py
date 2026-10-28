import re
import os
import tldextract
import requests
from config import (
    TLDEXTRACT_CACHE_DIR, RELATED_APEXES, HOST_HINT_BONUS,
    UNPROTECTED_CLEAN0_MIN_AD, RATIO_BLOCK, MARGIN_BLOCK,
    PROTECTED_REVIEW_MIN_AD, PROTECTED_REVIEW_RATIO,
)

# Отключаем SSL-верификацию для tldextract (корпоративный SSL-сертификат)
# Включается только явно: TLDEXTRACT_INSECURE=1 (на GitHub Actions не нужно).
if os.environ.get("TLDEXTRACT_INSECURE") == "1":
    _original_get = requests.get
    def _patched_get(*args, **kwargs):
        kwargs['verify'] = False
        return _original_get(*args, **kwargs)
    requests.get = _patched_get

_extract = tldextract.TLDExtract(cache_dir=str(TLDEXTRACT_CACHE_DIR))

# =============================================================================
# 1. ПРИЗНАКИ В URL ЗАПРОСОВ (идут в скоринг, см. urlscan_client.collect_scan_verdicts)
# =============================================================================
# Сильные признаки рекламы: специфичные пути/параметры рекламных запросов (+40 к ad_score и +1 к strong).
# Именно «strong» отличает реальную рекламу от обычного стороннего скрипта (CDN, виджет, API).
AD_STRONG_PATTERNS = [
    r"/pagead/", r"adsbygoogle", r"/gampad/", r"/ima3(\.js|/)", r"/(show|get)_?ads?\b",
    r"/adview\b", r"/adserver", r"/ads?/", r"/adv(ert)?/", r"/banners?/",
    r"/(openrtb2?|ortb)\b", r"prebid", r"/rtb/", r"/vast\b", r"/vmap\b", r"/vpaid\b",
    r"/(usersync|user_sync|user-sync|idsync|id_sync|cookiesync|cookie_sync|cookie-sync|setuid)\b",
    r"/(imp|impression)s?[/?]", r"/pixel(\.gif|\.png|\?|/)", r"/beacon\b",
    r"[?&]gdpr(_consent)?=", r"[?&]us_privacy=",              # типичные хвосты cookie-sync запросов
    r"/(ads|adv|adsbygoogle|gpt)\.js",
]

# Признаки трекеров/аналитики (+30 к ad_score, как и раньше).
AD_TRACKER_PATTERNS = [
    r"\/metrika\/", r"\/hit;", r"tracker\.", r"header-bidding", r"\/ads\/system\/",
    r"sync-loader", r"counter", r"analytics", r"gnezdo\.ru", r"fundingchoices",
    r"\/cm\.", r"context\.js", r"telemetry", r"adriver", r"bs\.serving-sys", r"advert", r"adfox",
    r"viqeo", r"vigo\.tech", r"embeds\.rambler",
    r"mc\.yandex\.[a-z]+/watch", r"/collect\b", r"clickstream",

    # --- Специфичные рекламные пути Росбалта/СМИ2 ---
    r"smi2\.ru\/newdata\/",
    r"\/advert\/",
    r"\/banners\/",
]

SYSTEM_ASSETS_PATTERNS = [
    r"\/dist\/client\/assets\/", r"\/dist\/client\/fonts\/", r"\/scrooge-client\/",
    r"\.hsmedia\.ru", r"\.viqeo\.tv", r"\.bbci\.co\.uk", r"\.bbc\.co\.uk", r"\.thetruestory\.news", r"cdn.*iportal\.ru"
]

_COMPILED_STRONG = [re.compile(p, re.IGNORECASE) for p in AD_STRONG_PATTERNS]
_COMPILED_TRACKER = [re.compile(p, re.IGNORECASE) for p in AD_TRACKER_PATTERNS]
_COMPILED_SYSTEM = [re.compile(p, re.IGNORECASE) for p in SYSTEM_ASSETS_PATTERNS]

def url_is_strong_ad(url):
    return any(p.search(url) for p in _COMPILED_STRONG)

def url_is_tracker(url):
    return any(p.search(url) for p in _COMPILED_TRACKER)

def url_is_system_asset(url):
    return any(p.search(url) for p in _COMPILED_SYSTEM)

# =============================================================================
# 2. НИКОГДА НЕ БЛОКИРОВАТЬ (уровень A): чистая инфраструктура — CDN, библиотеки, шрифты,
#    видеоплееры, фото/файлохостинги. Совпадение: точный домен или любой поддомен.
#    Сюда НЕ входят рекламные сервисы (googlesyndication, googletagmanager, smartadserver, lijit,
#    liadm, cloudflareinsights, html-load, connatix, openfpcdn ...): раньше они были в белом списке
#    и поэтому проходили как «OK» при любом ad-рейтинге. Теперь они в чёрном списке.
#    Чёрный список проверяется РАНЬШЕ этого списка.
# =============================================================================
NEVER_BLOCK_DOMAINS = [
    "ampproject.org", "apester.com", "avatars.mds.yandex.net", "brightcove.com",
    "brightcovecdn.com", "bunny.net", "cloudflare.com", "createjs.com", "directupload.eu",
    "disqus.com", "disquscdn.com", "dmcdn.net", "fastpic.org", "favicon.yandex.net", "gstatic.com",
    "googleapis.com", "googleusercontent.com", "gvt1.com", "hostingkartinok.com", "imageban.ru",
    "imgchest.com", "infogram.com", "jquery.com", "jsdelivr.net", "jwplayer.com", "kinescope.io",
    "kinescopecdn.net", "nflximg.net", "nnmstatic.win", "openstreetmap.org", "pic4net.com",
    "plyr.io", "rackcdn.com", "rutubelist.ru", "sentry.io", "sentry-saas.rambler-co.ru",
    "sketchfab.com", "thetruestory.news", "tildaapi.com", "tildacdn.com", "twimg.com", "unpkg.com",
    "viafoura.co", "viafoura.net", "vkuseraudio.net", "vkuserphoto.ru", "vkusernet.ru",
    "vk-cdn.net", "vkcloud-storage.ru", "vkvd.net", "wistia.com", "yapfiles.ru", "ytimg.com",
    "yastatic-net.ru", "nnmstatic.win", "rutracker.cc",
]

# =============================================================================
# 3. ЗАЩИЩЁННЫЕ СЕМЕЙСТВА (уровень B): крупные портальные экосистемы и сайты-источники.
#    Корень (apex и www.apex) блокировать нельзя — сломается сам сервис, но ПОДДОМЕНЫ блокируются, если
#    они в чёрном списке, имеют рекламный признак в имени (analytics.*, cm.*, ssp.*, stats.* ...)
#    или у них заметный перевес рекламных очков (см. decide()).
#    Раньше эти домены целиком лежали в белом списке — поэтому analytics.iportal.ru с ad=6510, clean=0
#    и cm.a.mts.ru с ad=252, clean=0 попадали в OK.
#    Семейства yandex.* и google.* определяются по apex (см. is_protected).
# =============================================================================
PROTECTED_FAMILIES = [
    # Яндекс / Google помимо yandex.* и google.*
    "ya.ru", "yastatic.net", "yandexcloud.net", "dzen.ru", "dzeninfra.ru", "youtube.com",
    # VK / Mail.ru / OK
    "mail.ru", "imgsmail.ru", "vk.com", "vk.ru", "vk.me", "vk.team", "vk-portal.net", "vkvideo.ru",
    "userapi.com", "ok.ru", "odnoklassniki.ru", "okcdn.ru", "mycdn.me",
    # Операторы, банки, госсервисы
    "mts.ru", "t2.ru", "beeline.ru", "sber.ru", "sberbank.ru", "sbrf.ru", "mos.ru",
    # Рамблер и холдинги
    "rambler.ru", "iportal.ru", "hsmedia.ru", "1mi-media.ru", "1mi.media", "kp.ru", "kpcdn.net",
    "rbk.ru", "rbc.ru", "rutube.ru", "openwebmp.com", "spot.im", "piano.io", "tinypass.com",
    # Yahoo
    "yahoo.com", "yahoo.net", "yimg.com", "oath.com", "yahoofinance.com",
    # Соцсети и крупные пользовательские сайты (корень нужен людям)
    "twitter.com", "x.com", "facebook.com", "instagram.com", "temu.com", "bing.com",
    "wildberries.ru",
    # Сайты-источники из urls.txt и их инфраструктура
    "bbc.com", "bbc.co.uk", "bbci.co.uk", "cnews.ru", "e1.ru", "euronews.com", "fishki.net", "fontanka.ru",
    "gazeta.ru", "ign.com", "interfax.ru", "ixbt.com", "iz.ru", "lenta.ru", "mk.ru",
    "ngs.ru", "pikabu.ru", "retail.ru", "rosbalt.ru", "techradar.com", "tourdom.ru", "vedomosti.ru",
    "vdmsti.ru", "yaplakal.com", "yuga.ru", "rferl.org", "thetruestory.news",
]

# =============================================================================
# 4. ЧЁРНЫЙ СПИСОК ПО APEX: рекламные/трекерные компании целиком (домен и все поддомены).
#    Нужен для сервисов, которые в логе висели как OK из-за малой выборки (1-2 запроса).
# =============================================================================
AD_APEX_BLACKLIST = {
    # Google ad stack (раньше googlesyndication/googletagmanager/google-analytics были в белом списке)
    "googlesyndication.com", "doubleclick.net", "googleadservices.com", "googletagservices.com",
    "googletagmanager.com", "google-analytics.com", "adservice.google.com", "googleoptimize.com",
    # Amazon / Microsoft / Adobe / Meta ad hosts
    "amazon-adsystem.com", "adsymptotic.com", "bat.bing.com", "c.bing.com", "everesttech.net",
    "omtrdc.net", "adobedtm.com",
    # Cloudflare / Datadog / fingerprint-аналитика, раньше в белом списке
    "cloudflareinsights.com", "browser-intake-datadoghq.com", "openfpcdn.io", "fpjscdn.net",
    "html-load.com",
    # Видео-реклама и ad-плееры
    "connatix.com", "coolbonsai.com", "injectoften.com", "aniview.com", "smartadserver.com",
    "stickyadstv.com", "spotxchange.com", "springserve.com", "teads.tv", "undertone.com",
    # SSP / DSP / DMP / cookie-sync / identity
    "33across.com", "3lift.com", "tynt.com", "adkernel.com", "admixer.net", "adhaven.com",
    "adspector.io", "adlook.tech", "adsource.pro", "admanmedia.com", "advcake.ru",
    "agkn.com", "amx1.net", "axis-marketplace.com", "blismedia.com", "bricks-co.com",
    "brandmetrics.com", "ck-ie.com", "clickagy.com", "contextweb.com", "cootlogix.com",
    "crwdcntrl.net", "digitaltarget.ru", "dmxleo.com", "dotomi.com", "doubleverify.com", "dv.tech",
    "eskimi.com", "exelator.com", "eyeota.net", "giraff.io", "giraff.media", "gumgum.com",
    "indexww.com", "infolinks.com", "inmobi.com", "iqzone.com", "kargo.com", "krushmedia.com",
    "krxd.net", "kueezrtb.com", "liadm.com", "lijit.com", "loopme.me", "marphezis.com",
    "measureadv.com", "mediagotechnology.com", "mobilefuse.com", "mookie1.com", "myweb3id.io",
    "nextmillmedia.com", "nodals.io", "omnitagjs.com", "onetag-sys.com", "acuityplatform.com",
    "perfluence.net", "permutive.app", "permutive.com", "prmutv.co", "postrelease.com",
    "programmaticx.ai", "punchmedia.ru", "qtarget.tech", "rlcdn.com", "rqtrk.eu", "rtbcdn.ru",
    "rtbwave.com", "rtactivate.com", "rutarget.ru", "semasio.net", "seedtag.com", "servenobid.com",
    "sharethrough.com", "silvermob.com", "simpli.fi", "skimresources.com", "smilewanted.com",
    "sonobi.com", "svk-native.ru", "syncingbridge.com", "targetrtb.com", "thrtle.com",
    "tracookiepixel.xyz", "travelpayouts.com", "trustedstack.com", "ussp.io", "utraff.com",
    "uuidksinc.net", "videohead.tech", "vistarsagency.com", "whiteboxdigital.ru", "xoalt.com",
    "yellowblue.io", "yieldmo.com", "ymmobi.com", "zemanta.com", "zdbb.net", "mradx.net",
    "rmp.rakuten.com", "addthis.com", "quantserve.com", "taboola.com", "criteo.net",
    "sascdn.com", "dotmetrics.net", "moatads.com", "adsafeprotected.com", "adform.net", "adition.com", "yandexadexchange.net",
}

# Дополнительные точечные правила для хостов внутри «защищённых» семейств
# (подмножество рекламной/телеметрической инфраструктуры Яндекса, VK/Mail.ru, МТС, Рамблера, Yahoo и др.)
EXTRA_BLACKLIST_PATTERNS = [
    r"(^|\.)a\.mts\.ru$",                              # МТС Реклама: cm.a.mts.ru, api.a.mts.ru, static.a.mts.ru
    r"^abt\.s3\.yandex\.net$",                         # A/B-тесты Яндекса
    r"^uaas\.yandex\.ru$",                             # Эксперименты Яндекса
    r"^privacy-cs\.mail\.ru$",                         # Cookie-sync Mail.ru Group
    r"^media-(sensor|stat|trend)\.mail\.ru$",          # Счётчики медиа-рекламы Mail.ru
    r"(^|\.)media-advcycle\.imgsmail\.ru$",
    r"^(kraken(-[a-z0-9]+)?)\.[a-z0-9.\-]+$",          # kraken.* — рекламная/аналитическая платформа (Рамблер, IGN/Ziff Davis)
    r"^rcm(-tr|js)?\.rambler\.ru$",                  # Рекомендательные рекламные узлы Рамблера
    r"^pbs\.yahoo\.com$",                              # Prebid Server Yahoo
    r"^fundingchoicesmessages\.google\.com$",          # Google Funding Choices (anti-adblock стена)
    r"^imasdk\.googleapis\.com$",                      # Google IMA SDK (видеореклама)
    r"^pagead\d*\.",                                   # pagead2.* и аналоги
    r"^cs\.openwebmp\.com$",                           # Cookie-sync OpenWeb
    r"^gurgle\.[a-z0-9.\-]+$",                         # Телеметрия Ziff Davis / IGN
    r"^hawk\.techradar\.com$",                         # Телеметрия Future plc
    r"^ext\.clickstream\.sbrf\.ru$",                   # Clickstream Сбера
    r"^stats?\.vk-portal\.net$",                       # Статистика VK
]

# --- ЧЕРНЫЙ СПИСОК (Паттерны блокировки рекламы и трекеров) ---
STRICT_SUBDOMAINS_BLACKLIST_PATTERNS = [
    # === NUMBERS / SYMBOLS ===
    r"(^|\.)24smi\.(net|info)$",                     # Тизерная сеть 24СМИ (объединено .net и .info)

    # === A ===
    r"(^|\.)1dmp\.io$",                              # Синхронизатор данных DMP (Из NEED_REVIEW)
    r"(^|\.)360yield\.com$",                         # Рекламная SSP-платформа Yieldmo / 360yield (Из NEED_REVIEW)
    r"(^|\.)acint\.net$",                            # Рекплатформа и синхронизатор Acint
    r"(^|\.)ad-delivery\.net$",                      # Сеть доставки рекламы Ad-Delivery
    r"(^|\.)adentifi\.com$",                         # Идентификационный рекламный трекер Adentifi (Из NEED_REVIEW)
    r"(^|\.)adiam\.tech$",                           # Рекламные технологии Adiam (Из NEED_REVIEW)
    r"(^|\.)adlook\.online$",                        # Реклатформа Adlook (Из NEED_REVIEW)
    r"(^|\.)admatic\.(com\.tr|de)$",                 # Рекламные сети Admatic Turkey/Germany (Из NEED_REVIEW)
    r"(^|\.)adriver\.ru$",                           # Медиа-трекер Adriver
    r"(^|\.)adsrvr\.org$",                           # Рекламная платформа The Trade Desk / match.adsrvr (Из NEED_REVIEW)
    r"(^|\.)adtarget\.biz$",                         # Programmatic-платформа Adtarget.biz (Из NEED_REVIEW)
    r"(^|\.)adverticum\.com$",                       # Провайдер баннеров
    r"(^|\.)adhigh\.net$",                           # Рекламный пиксель и трекер AdHigh
    r"(^|\.)adnxs\.com$",                            # Рекламная RTB-биржа AppNexus
    r"(^|\.)adseedtech\.com$",                       # Зарубежная рекламная RTB-биржа / SSP
    r"^[a-z0-9\-]+\.adfox\.ru$",                     # Динамический таргетинг AdFox
    r"(^|\.)adserver\.gear-hub\.ru$",                # Локальный adserver / Gear-Hub
    r"(^|\.)adsp\.io$",                              # Рекламный синхронизатор Adsp (Из NEED_REVIEW)
    r"(^|\.)adx\.(com\.ru|videonow\.ru)$",           # Биржи AdX (объединены adx.com.ru и adx.videonow.ru)
    r"(^|\.)alfasense\.com$",                        # Рекламная платформа Alfasense (://alfasense.com)
    r"(^|\.)a-mo\.net$",                             # Рекламная RTB-сеть A-Mo / prebid.a-mo (Из NEED_REVIEW)
    r"(^|\.)apptracer\.ru$",                         # Трекер мобильной и веб-аналитики Apptracer
    r"(^|\.)appsflyersdk\.com$",                     # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)arcspire\.io$",                          # Рекламный пиксель Arcspire (Из NEED_REVIEW)

    # === B ===
    r"(^|\.)bestdahlia\.com$",                       # Рекламная синхронизация кук Bestdahlia
    r"(^|\.)betweendigital\.com$",                   # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)bidderstack\.com$",                      # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)bidswitch\.net$",                        # Платформа обмена трафиком BidSwitch / x.bidswitch (Из NEED_REVIEW)
    r"(^|\.)bidvol\.com$",                           # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)bumlam\.com$",                           # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)buzzoola\.com$",                         # Зарубежная рекламная RTB-биржа / SSP

    # === C ===
    r"(^|\.)casalemedia\.com$",                      # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)chartbeat\.(net|org)$",                  # Избыточный трекер пинга Chartbeat / ping.chartbeat (Из NEED_REVIEW)
    r"(^|\.)criteo\.com$",                           # Ретаргетинг и синхронизация Criteo / ssp-sync (Из NEED_REVIEW)
    r"(^|\.)cxense\.com$",                           # Аналитическая и рекомендательная платформа Cxense

    # === D ===
    r"(^|\.)2mdn\.net$",                             # Зеркало doubleclick, используемое для отслеживания (Из NEED_REVIEW)
    r"(^|\.)demdex\.net$",                           # Платформа управления данными Adobe AudienceManager (dpm.demdex.net)
    r"(^|\.)dynotech\.io$",                          # Рекламный шлюз Dynotech RTB (Из NEED_REVIEW)

    # === F ===
    r"(^|\.)facecast\.net$",                         # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)futurecdn\.net$",                        # Коммерческие контент-трекеры издателя Future / freyr (Из NEED_REVIEW)
    r"(^|\.)fwmrm\.net$",                            # Синхронизация профилей FreeWheel / user-sync (Из NEED_REVIEW)

    # === G ===
    r"(^|\.)gamoshi\.io$",                           # Рекламная programmatic-платформа Gamoshi (Из NEED_REVIEW)
    r"(^|\.)gnezdo\.ru$",                            # Тизерная сеть Гнездо
    r"(^|\.)gonet-ads\.com$",                        # Рекламная сеть GoNet (Из NEED_REVIEW)

    # === H ===
    r"(^|\.)hybrid\.ai$",                            # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)hbrd\.io$",                              # Зарубежная рекламная RTB-биржа / SSP
    r"^px\.hsmedia\.ru$",                            # Медиа-трекер Hearst Shkulev Media

    # === I ===
    r"(^|\.)id5-sync\.com$",                         # Платформа идентификации пользователей ID5 (Из NEED_REVIEW)
    r"(^|\.)intent\.ai$",                            # Платформа таргетинга Intent.AI (Из NEED_REVIEW)

    # === L ===
    r"(^|\.)linkedin\.com$",                         # Рекламный пиксель отслеживания LinkedIn / px.ads (Из NEED_REVIEW)
    r"(^|\.)lentainform\.ru$",                       # Тизерная сеть Лентаинформ
    r"(^|\.)linkssp\.ru$",                           # Рекламообменная сеть SSP
    r"(^|\.)lotus-dsp\.ru$",                         # Рекламная платформа Lotus DSP

    # === M ===
    r"^ad\.mail\.ru$",                               # Рекламная экосистема VK / Mail.ru
    r"^reklama\.mail\.ru$",                          # Рекламная экосистема VK / Mail.ru
    r"^top(-[a-z0-9]+)?\.mail\.ru$",                 # Трекер Top.Mail.ru
    r"(^|\.)marketgid\.com$",                        # Старая тизерная сеть / MGID
    r"(^|\.)media\.net$",                            # Рекламная сеть Yahoo/Bing Contextual / cs.media.net (Из NEED_REVIEW)
    r"(^|\.)mediadash\.ru$",                         # Аналитика и трекинг Mediadash
    r"(^|\.)mediascope\.net$",                       # Аналитика Mediascope
    r"(^|\.)mediatoday\.ru$",                        # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)mgid\.com$",                             # Глобальный медиа-агрегатор рекламы
    r"(^|\.)mindbox\.ru$",                           # Платформа автоматизации маркетинга и трекинга Mindbox
    r"(^|\.)mirtesen\.ru$",                          # Рекомендательная сеть МирТесен
    r"(^|\.)moe\.video$",                            # Рекламная видеосеть MoeVideo (cdn1 / rtb)
    r"(^|\.)mpartner\.digital$",                     # Рекламный programmatic-шлюз Mpartner (Из NEED_REVIEW)
    r"(^|\.)mrgcdn\.ru$",                            # Медиа-трекеры / CDN Mail.ru

    # === N ===
    r"(^|\.)new-programmatic\.com$",                 # Синхронизатор кук New Programmatic (Из NEED_REVIEW)

    # === O ===
    r"(^|\.)ohmy\.bid$",                             # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)onesignal\.com$",                        # Маркетинговые пуш-уведомления OneSignal
    r"(^|\.)openx\.net$",                            # Крупная рекламная биржа OpenX RTB / rtb.openx (Из NEED_REVIEW)
    r"(^|\.)opti-digital\.com$",                     # Рекламная монетизация Opti-Digital (включая .optidigital.com)
    r"(^|\.)optidigital\.com$",                      # Дублирующий корень Opti-Digital
    r"(^|\.)optimizely\.com$",                       # Платформа A/B тестирования и трекинга Optimizely
    r"(^|\.)openssp\.ru$",                           # Рекламный шлюз OpenSSP (asr.openssp.ru)
    r"^t\.adx\.opera\.com$",                         # Рекламный движок встроенной рекламы браузера Opera
    r"(^|\.)otm-r\.com$",                            # Рекламная сеть OTM (://otm-r.com)
    r"(^|\.)outbrain\.com$",                         # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)outbrainimg\.com$",                      # Зарубежная рекламная RTB-биржа / SSP

    # === P ===
    r"(^|\.)plusoneads\.com$",                       # Рекламная монетизация PlusOne / sync.plusoneads (Из NEED_REVIEW)
    r"(^|\.)presage\.io$",                           # Мобильный рекламный трекер Presage
    r"(^|\.)pubmatic\.com$",                         # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)push4site\.com$",                        # Пуш-уведомления и реклама Push4site

    # === Q ===
    r"(^|\.)q-bid\.ru$",                             # Рекламная биржа Q-Bid (Из NEED_REVIEW)

    # === R ===
    r"^embeds\.rambler\.ru$",                        # Рекламные сети Рамблера
    r"^pixel\.rambler\.ru$",                         # Пиксель Рамблера
    r"^ssp01?\.rambler\.ru$",                        # Объединенное правило для ssp.rambler.ru и ssp01.rambler.ru
    r"(^|\.)rambler\.ru/banner",                     # Баннерная статика Рамблера
    r"(^|\.)relap\.io$",                             # Нативная реклама Relap
    r"^goya\.rutube\.ru$",                           # Видео-реклама Rutube
    r"^ssp\.rutube\.ru$",                            # Рекламный движок Rutube
    r"(^|\.)log\.rutube\.ru$",                       # Трекер Rutube
    r"(^|\.)rubiconproject\.com$",                   # Реклатформа Rubicon Project / Magnite (Из NEED_REVIEW)

    # === S ===
    r"(^|\.)sape\.ru$",                              # Рекламно-ссылочная биржа Sape (cdn-rtb / ssp-rtb)
    r"(^|\.)sbermarketing\.ru$",                     # Рекламный трекер СберМаркетинг (dmp.sbermarketing.ru)
    r"(^|\.)scorecardresearch\.com$",                # Глобальный трекер Comscore
    r"(^|\.)sitescout\.com$",                        # Мобильная DSP-платформа Centro / pixel-sync (Из NEED_REVIEW)
    r"(^|\.)skcrtxr\.com$",                          # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)smartcallback\.ru$",                     # Маркетинговый трекер SmartCallback
    r"(^|\.)smi2\.(ru|net)$",                        # Обменник и зеркала СМИ2 (объединено .ru и .net)
    r"(^|\.)smi2cdn\.ru$",                           # Рекламный CDN сети СМИ2
    r"(^|\.)sparrow\.ru$",                           # Тизерная и рекламная сеть Sparrow (widget.sparrow.ru)
    r"(^|\.)stbid\.ru$",                             # Блокирует stbid.ru со ВСЕМИ поддоменами целиком
    r"(^|\.)supercdn\.ru$",                          # Рекламный CDN медиахолдингов

    # === T ===
    r"(^|\.)tapad\.com$",                            # Кросс-девайс трекер MarTech / pixel.tapad (Из NEED_REVIEW)
    r"(^|\.)terratraf\.com$",                        # Тизерная и баннерная сеть TerraTraf (Из NEED_REVIEW)
    r"(^|\.)tns-counter\.ru$",                       # Mediascope (бывший TNS)

    # === U ===
    r"(^|\.)4dex\.io$",                              # Рекламный programmatic-движок 4Dex / u-ams / u-las (Из NEED_REVIEW)
    r"(^|\.)upravel\.com$",                          # Маркетинговый трекер Upravel (Из NEED_REVIEW)

    # === V ===
    r"^(adx|sync)\.videonow\.ru$",
    r"(^|\.)vdo\.ai$",                               # Видео-рекламная сеть Vdo.ai / ortb.vdo (Из NEED_REVIEW)
    r"(^|\.)viadata\.store$",                        # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)vigo\.tech$",                            # Медиа-метрики Vigo
    r"(^|\.)viqeo\.tv$",                             # Видео-трекеры Viqeo
    r"(^|\.)voxexchange\.io$",                       # Биржа SSP / VoxExchange
    r"(^|\.)tracker-api\.vk-analytics\.ru$",         # Рекламная экосистема VK / Mail.ru

    # === W ===
    r"(^|\.)weborama\.fr$",                          # Зарубежная рекламная RTB-биржа / SSP
    r"(^|\.)weborama-tech\.ru$",                     # Рекламные трекеры Weborama

    # === Y ===
    r"^analytics.*\.yahoo\.[a-z]+$",                 # Метрики Yahoo
    r"^geo\.yahoo\.com$",                            # Гео-трекер Yahoo (исправлена критическая блокировка корня)
    r"^(an|mc|ads|awaps|bs|context|direct|pagead)\.yandex\.[a-z]+$",  # Таргетированная реклама и метрики Яндекса
    r"^yandex-(dmp-)?sync\.rutarget\.ru$",           # Синхронизация Яндекса на Rutarget (Из NEED_REVIEW)
    r"(^|\.)log\.strm\.yandex\.ru$",                 # Метрики Яндекс Стриминга
]

# Объединяем все точечные правила в один список (старые + дополнительные)
STRICT_SUBDOMAINS_BLACKLIST_PATTERNS = STRICT_SUBDOMAINS_BLACKLIST_PATTERNS + EXTRA_BLACKLIST_PATTERNS

# --- Паттерны для детекции динамических хэш-поддоменов ---
_IS_HASH_PATTERNS = [
    re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),             # MD5 (Google safeframe и др.)
    re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-", re.IGNORECASE),  # Часть UUID
    re.compile(r"^\d{6,}$"),                                   # Чисто числовые ID от 6 знаков
]

_COMPILED_BLACKLIST_PATTERNS = [re.compile(pat, re.IGNORECASE) for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS]

# Уровни решения
BLOCK, REVIEW, ALLOW = "block", "review", "allow"


def _extract_domain_regex(url):
    match = re.search(r"https?://([^/:]+)", url)
    return match.group(1).lower() if match else None

def get_apex_domain(url):
    if not url or url.startswith("data:"):
        return None
    try:
        extracted = _extract(url if url.startswith(("http://", "https://")) else f"http://{url}")
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    except Exception:
        pass
    domain = _extract_domain_regex(url)
    return domain if domain else None

def _in_list(domain, entries):
    """Точное совпадение или поддомен записи (а не подстрока: notyahoo.com != yahoo.com)."""
    return any(domain == e or domain.endswith("." + e) for e in entries)

def is_hard_blacklisted(domain):
    """True, если домен (или его apex) явно в чёрном списке: AD_APEX_BLACKLIST или STRICT_SUBDOMAINS_BLACKLIST_PATTERNS.
    Такие домены блокируются независимо от скоринга и белых списков."""
    domain = domain.lower().strip().rstrip(".")
    if _in_list(domain, AD_APEX_BLACKLIST):
        return True
    apex = get_apex_domain(domain)
    return any(pat.search(domain) or (apex and pat.search(apex)) for pat in _COMPILED_BLACKLIST_PATTERNS)

def is_protected(domain, apex=None):
    """Домен принадлежит «защищённому семейству»: корень блокировать нельзя, поддомены — по признакам."""
    apex = apex or get_apex_domain(domain) or domain
    if apex.startswith("google.") or apex.startswith("yandex."):
        return True
    return _in_list(domain, PROTECTED_FAMILIES)

def is_never_block(domain):
    return _in_list(domain, NEVER_BLOCK_DOMAINS)

def is_same_site(url, seed_apex):
    """True, если URL принадлежит сайту сида: тот же apex-домен (любой поддомен) или явно связанный из RELATED_APEXES."""
    apex = get_apex_domain(url)
    if not apex or not seed_apex:
        return False
    return apex == seed_apex or apex in RELATED_APEXES.get(seed_apex, ())

# --- Рекламные признаки в имени хоста ---
_AD_HOST_LABELS = {
    "ad", "ads", "adx", "adv", "adserver", "adserv", "adsrv", "adtech", "adnetwork",
    "ssp", "dsp", "dmp", "rtb", "bid", "bidder", "prebid", "pixel", "px",
    "sync", "usersync", "idsync", "cookiesync", "cm", "match",
    "track", "tracker", "tracking", "beacon", "collect", "counter",
    "analytics", "metrika", "metrics", "telemetry", "stat", "stats", "clickstream",
}
_AD_LABEL_SUFFIX_RE = re.compile(r"[a-z]{2,}(ssp|dsp|rtb)$")   # ussp, amxrtb, colossusssp, kueezrtb

def host_ad_hint(domain):
    """True, если среди меток хоста (без TLD, с разбиением по дефису, без хвостовых цифр) есть рекламный термин:
    ads, ssp, dsp, rtb, px, sync, cm, analytics, stats ..."""
    for part in domain.lower().split(".")[:-1]:
        for label in part.split("-"):
            label = re.sub(r"\d+$", "", label)
            if label in _AD_HOST_LABELS or _AD_LABEL_SUFFIX_RE.match(label):
                return True
    return False

def service_group_key(domain):
    """Ключ «одного сервиса»: реплики вида hal9000.x.net / hal90005.x.net, px2.x.pro / px4.x.pro, cs13.x.ru / cs2.x.ru
    получают общий ключ (первая метка без хвостовых цифр). У доменов 2-го уровня ключ — сам домен."""
    domain = domain.lower().strip()
    parts = domain.split(".")
    if len(parts) < 3:
        return domain
    stripped = re.sub(r"\d+$", "", parts[0]) or "#"
    return ".".join([stripped] + parts[1:])


def decide(domain, score=None, own_site=False):
    """
    Единое решение по домену. Возвращает BLOCK (идёт в hosts), REVIEW (не блокируется, показывается в логе
    для ручного решения) или ALLOW.

    Порядок проверок:
      1. Чёрный список (apex-список и регулярки)  -> BLOCK. Проверяется ПЕРВЫМ, белые списки его не перекрывают.
      2. Чистая инфраструктура (NEVER_BLOCK)       -> ALLOW.
      3. Защищённые семейства и «свой» сайт сида: корень -> ALLOW; поддомен с рекламным признаком
         в имени / сильными рекламными URL и перевесом ad над clean -> BLOCK.
      4. Остальные (неизвестные сторонние домены): clean == 0 и хоть какой-то рекламный след -> BLOCK;
         иначе перевес ad над clean по порогам.
    score: {"clean_score", "ad_score", "strong", "hint"}; None — данных нет (старые записи hosts, схлопнутые хэши).
    """
    domain = domain.lower().strip().rstrip(".")
    if is_hard_blacklisted(domain):
        return BLOCK
    if is_never_block(domain):
        return ALLOW

    apex = get_apex_domain(domain) or domain
    protected = own_site or is_protected(domain, apex)
    is_root = domain == apex or domain == f"www.{apex}"
    hint = host_ad_hint(domain) or bool(score and score.get("hint"))

    if score is None:
        if protected:
            return BLOCK if (hint and not is_root) else ALLOW
        return BLOCK

    clean = score.get("clean_score", 0)
    ad = score.get("ad_score", 0)
    strong = score.get("strong", 0)

    if protected:
        if is_root:
            return ALLOW
        if hint:
            return BLOCK if ad >= clean else REVIEW
        if strong:
            if ad > clean * RATIO_BLOCK + MARGIN_BLOCK:
                return BLOCK
            return REVIEW if ad > clean else ALLOW
        # Без признаков в имени и без сильных URL: автоматически не блокируем (скоринг считает «рекламой»
        # любой сторонний скрипт/API — news.google.com, api.vkvideo.ru, cs.rambler.ru), но сильный перекос
        # выносим в REVIEW, чтобы решение принял человек (добавить в чёрный список или оставить).
        if ad >= PROTECTED_REVIEW_MIN_AD and (clean == 0 or ad > clean * PROTECTED_REVIEW_RATIO):
            return REVIEW
        return ALLOW

    # Неизвестный сторонний домен
    if hint or strong:
        return BLOCK if ad >= clean else REVIEW
    if clean == 0:
        return BLOCK if ad >= UNPROTECTED_CLEAN0_MIN_AD else ALLOW
    if ad > clean * RATIO_BLOCK + MARGIN_BLOCK:
        return BLOCK
    return REVIEW if ad > clean else ALLOW

def should_block_domain(domain, page_apex=None, score=None, own_site=False):
    """Совместимая обёртка: True, если decide() даёт BLOCK."""
    if page_apex and not own_site:
        d = domain.lower().strip()
        own_site = get_apex_domain(d) == page_apex or f"www.{d}" == page_apex
    return decide(domain, score=score, own_site=own_site) == BLOCK


def classify_session(domain_stats):
    """
    Единое решение по домену на основе очков со ВСЕХ страниц сессии (а не последней страницы).
    domain_stats: {domain: {"clean_score", "ad_score", "strong", "pages", "own_site"}}.
    Реплики одного сервиса (service_group_key) оцениваются по суммарным очкам группы;
    рекламный признак в имени хоста добавляет HOST_HINT_BONUS один раз на группу.
    Возвращает (ad_domains, review_domains, clean_domains); в записях clean_score/ad_score — итоговые очки решения.
    """
    groups = {}
    for d in domain_stats:
        groups.setdefault(service_group_key(d), []).append(d)

    ad_domains, review_domains, clean_domains = {}, {}, {}
    for members in groups.values():
        clean = sum(domain_stats[m].get("clean_score", 0) for m in members)
        ad = sum(domain_stats[m].get("ad_score", 0) for m in members)
        strong = sum(domain_stats[m].get("strong", 0) for m in members)
        own_site = any(domain_stats[m].get("own_site") for m in members)
        hint = any(host_ad_hint(m) for m in members)
        if hint:
            ad += HOST_HINT_BONUS
        for d in members:
            entry = {
                "clean_score": clean, "ad_score": ad, "strong": strong,
                "pages": domain_stats[d].get("pages", 1),
                "group": len(members), "hint": hint,
            }
            level = decide(d, score=entry, own_site=own_site)
            if level == BLOCK:
                ad_domains[d] = entry
            elif level == REVIEW:
                review_domains[d] = entry
            else:
                clean_domains[d] = entry
    return ad_domains, review_domains, clean_domains

def _is_hash(left_segment):
    """Проверяет, является ли сегмент домена хэшем или идентификатором."""
    if any(pat.search(left_segment) for pat in _IS_HASH_PATTERNS):
        return True
    # Хэши с дефисами (буквы + цифры)
    if "-" in left_segment and len(re.findall(r"[a-z0-9]", left_segment)) > 15:
        return True
    return False

def normalize_and_detect_dynamic_domain(domain):
    """
    Схлопывает ТОЛЬКО одноразовые поддомены с хэш/ID-метками (hosts не умеет wildcard, а хэшей бесконечно много).
    Обычные (не хэшированные) хосты остаются как есть: в hosts.txt каждый поддомен должен быть перечислен явно,
    иначе pubads.g.doubleclick.net перестанет блокироваться, если в списке остался только doubleclick.net.
      * Хэш-хост под рекламным apex из чёрного списка -> сам apex (stbid.ru, googlesyndication.com).
      * Иначе ведущие хэш-метки отбрасываются, остаётся родительский хост:
        1766...cm.a.mts.ru -> cm.a.mts.ru (раньше схлопывалось до mts.ru, который защищён, и реклама терялась).
    Возвращает (is_dynamic, normalized_domain).
    """
    domain = domain.lower().strip()
    parts = domain.split('.')
    apex = get_apex_domain(domain)
    if not apex:
        return False, domain
    apex_len = len(apex.split('.'))
    if len(parts) <= apex_len:
        return False, domain   # корень: ничего не схлопываем

    # Особый случай Дзена: изолируем только рекламные узлы, остальной dzen.ru защищён
    if apex == "dzen.ru":
        for sub in ["cu.dzen.ru", "ms.dzen.ru"]:
            if sub in domain:
                return True, sub
        return False, domain

    prefix = parts[:len(parts) - apex_len]
    if not any(_is_hash(label) for label in prefix):
        return False, domain   # обычный хост — оставляем явной записью

    # Хэш-хост под рекламным apex: блокируем корень (в adblock.txt это покрывает все поддомены)
    if _in_list(apex, AD_APEX_BLACKLIST) or any(pat.search(apex) for pat in _COMPILED_BLACKLIST_PATTERNS):
        return True, apex

    # Иначе отбрасываем ведущие хэш-метки и оставляем родительский хост
    stripped = list(parts)
    while len(stripped) > apex_len and _is_hash(stripped[0]):
        stripped.pop(0)
    return True, ".".join(stripped)

def sort_domains_by_level(domains):
    """Сортирует по apex-домену, внутри — по уровню вложенности, затем алфавитно."""
    def sort_key(d):
        apex = get_apex_domain(d) or d
        depth = len(d.split(".")) - len(apex.split("."))
        return (apex, depth, d)
    return sorted(domains, key=sort_key)
