import re
import os
import tldextract
import requests
from config import TLDEXTRACT_CACHE_DIR, RELATED_APEXES, STRICT_BAN_RATIO, STRICT_BAN_MARGIN, HOST_HINT_BONUS

# Отключаем SSL-верификацию для tldextract (корпоративный SSL-сертификат)
# Включается только явно: TLDEXTRACT_INSECURE=1 (на GitHub Actions не нужно).
if os.environ.get("TLDEXTRACT_INSECURE") == "1":
    _original_get = requests.get
    def _patched_get(*args, **kwargs):
        kwargs['verify'] = False
        return _original_get(*args, **kwargs)
    requests.get = _patched_get

_extract = tldextract.TLDExtract(cache_dir=str(TLDEXTRACT_CACHE_DIR))

# --- Паттерны для скоринговой системы ---
AD_TRACKER_PATTERNS = [
    r"\/metrika\/", r"\/hit;", r"tracker\.", r"header-bidding", r"\/ads\/system\/", 
    r"sync-loader", r"counter", r"analytics", r"gnezdo\.ru", r"fundingchoices", 
    r"\/cm\.", r"context\.js", r"telemetry", r"adriver", r"bs\.serving-sys", r"advert", r"adfox",
    r"viqeo", r"vigo\.tech", r"embeds\.rambler",

    # --- Специфичные рекламные пути Росбалта/СМИ2 ---
    r"smi2\.ru\/newdata\/",       # Конкретный подпуть редиректов СМИ2
    r"\/advert\/",                # Общие рекламные каталоги
    r"\/banners\/"                # Пути к статическим баннерам медиахолдингов
]

SYSTEM_ASSETS_PATTERNS = [
    r"\/dist\/client\/assets\/", r"\/dist\/client\/fonts\/", r"\/scrooge-client\/",
    r"\.hsmedia\.ru", r"\.viqeo\.tv", r"\.bbci\.co\.uk", r"\.bbc\.co\.uk", r"\.thetruestory\.news", r"cdn.*iportal\.ru"
]

# --- ЕДИНЫЙ БЕЛЫЙ СПИСОК: infrastructure медиа-холдингов, веб-платформы, CDN и глобальные сервисы ---
# Совпадение: точный домен или любой его поддомен (см. _in_list).
STRICT_DOMAINS_WHITELIST = [
    # === 0-9 ===
    "1mi-media.ru",                     # Экосистема Росбалт

    # === A ===
    "ampproject.org",                   # Служебная инфраструктура Google AMP
    "apester.com",                      # Интерактивный контент
    "avatars.mds.yandex.net",           # Экосистема Яндекс / Дзен (Служебные CDN)

    # === B ===
    "bbc.co.uk",                        # Государственные, банковские и новостные ресурсы
    "bbc.com",                          # Государственные, банковские и новостные ресурсы
    "brightcove.com",                   # Плееры Brightcove (BBC, Аль-Джазира и др.)
    "brightcovecdn.com",                # Статика и медиа-потоки Brightcove
    "browser-intake-datadoghq.com",     # Системные CDN и библиотеки
    "bunny.net",                        # Bunny Stream инфраструктура

    # === C ===
    "cloudflare.com",                   # Глобальные CDN и служебная инфраструктура Google/Cloud
    "cloudflareinsights.com",           # Мониторинг производительности и JS-аналитика Cloudflare
    "cnews.ru",                         # Издание CNews
    "coolbonsai.com",                   # Служебное контентное зеркало Connatix
    "createjs.com",                     # Системные CDN, библиотеки и медиа-инфраструктура

    # === D ===
    "directupload.eu",                  # Фотохостинги и файловые хранилища
    "disqus.com",                       # Платформа комментариев Disqus
    "disquscdn.com",                    # CDN статики для комментариев Disqus
    "dmcdn.net",                        # Медиа-контент и видеохостинги (DailyMotion)
    "dzen.ru",                          # Экосистема Яндекс / Дзен
    "dzeninfra.ru",                     # Экосистема Яндекс / Дзен

    # === E ===
    "e1.ru",                            # Городские порталы Шкулёв Медиа
    "emp.bbci.co.uk",                   # Элементы плеера BBC

    # === F ===
    "fastpic.org",                      # Фотохостинги и файловые хранилища
    "favicon.yandex.net",               # Экосистема Яндекс / Дзен (Иконки)
    "files.1mi.media",                  # Медиа-ресурсы холдинга 1МИ
    "fontanka.ru",                      # Городские порталы Шкулёв Медиа

    # === G ===
    "gazeta.ru",                        # Экосистема Газета.ru (Служебные домены)
    "google-analytics.com",             # Глобальные CDN и служебная инфраструктура Google
    "google.com",                       # Глобальные CDN и служебная инфраструктура Google
    "google.dk",                        # Глобальные CDN и служебная инфраструктура Google
    "googleapis.com",                   # Глобальные CDN и служебная инфраструктура Google
    "googlesyndication.com",            # Глобальные CDN и служебная инфраструктура Google
    "googletagmanager.com",             # Глобальные CDN и служебная инфраструктура Google
    "googletagservices.com",            # Глобальные CDN и служебная инфраструктура Google
    "googleusercontent.com",            # Глобальные CDN и служебная инфраструктура Google
    "gstatic.com",                      # Глобальные CDN и служебная инфраструктура Google
    "gvt1.com",                         # Глобальные CDN и служебная инфраструктура Google

    # === H ===
    "hostingkartinok.com",              # Фотохостинги и файловые хранилища
    "html-load.com",                    # Инфраструктура доставки и оптимизации контента
    "hsmedia.ru",                       # Инфраструктура Hearst Shkulev Media

    # === I ===
    "ichef.bbci.co.uk",                 # Изображения BBC
    "imageban.ru",                      # Фотохостинги и файловые хранилища
    "imgchest.com",                     # Фотохостинги и файловые хранилища
    "imgsmail.ru",                      # Экосистема VK / Mail.ru
    "infogram.com",                     # Инфографика и интерактивные чарты
    "injectoften.com",                  # Служебный домен доставки плеера Connatix
    "iportal.ru",                       # Городские порталы холдинга Shkulev Media

    # === J ===
    "jquery.com",                       # Системные CDN, библиотеки и медиа-инфраструктура
    "jsdelivr.net",                     # Глобальные CDN и служебная инфраструктура
    "jwplayer.com",                     # Независимые плееры JW Player в СМИ

    # === K ===
    "kinescope.io",                     # Видеохостинг и стриминг Kinescope
    "kinescopecdn.net",                 # Распределенная сеть доставки видео Kinescope
    "kp.ru",                            # Экосистема КП (Комсомольская Правда)
    "kpcdn.net",                        # Инфраструктура Комсомольской Правды

    # === L ===
    "liadm.com",                        # Инфраструктура контентной оптимизации LiveIntent
    "lijit.com",                        # Медиа-инфраструктура и контентные виджеты

    # === M ===
    "mail.ru",                          # Экосистема VK / Mail.ru
    "mos.ru",                           # Государственные, банковские и новостные ресурсы
    "mts.ru",                           # Экосистема МТС
    "mybbc-analytics.files.bbci.co.uk", # Аналитические файлы BBC
    "mycdn.me",                         # Экосистема VK / Одноклассники

    # === N ===
    "nflximg.net",                      # Медиа-контент (Netflix CDN)
    "ngs.ru",                           # Городские порталы Шкулёв Медиа
    "nnmstatic.win",                    # Торрент-трекеры и их статика

    # === O ===
    "oath.com",                         # Окно согласия с условиями использования (Privacy GDPR) для Yahoo
    "odnoklassniki.ru",                 # Одноклассники
    "ok.ru",                            # Одноклассники
    "okcdn.ru",                         # Одноклассники CDN
    "openfpcdn.io",                     # Системные CDN, библиотеки и медиа-инфраструктура
    "openstreetmap.org",                # Картографический сервис
    "openwebmp.com",                    # Платформа комментариев OpenWeb

    # === P ===
    "piano.io",                         # Инфраструктура подписок Ведомостей/СМИ
    "pic4net.com",                      # Фотохостинги и файловые хранилища
    "plyr.io",                          # Системные CDN, библиотеки и медиа-инфраструктура

    # === R ===
    "r.mradx.net",                      # Экосистема VK / Mail.ru
    "rackcdn.com",                      # Медиа-контент и видеохостинги
    "rambler.ru",                       # Portal и медиа-сервисы Рамблера
    "rbk.ru",                           # Инфраструктура холдинга РБК
    "rferl.org",                        # Государственные, банковские и новостные ресурсы
    "rosbalt.ru",                       # Экосистема Росбалт
    "rutracker.cc",                     # Торрент-трекеры и их статика
    "rutube.ru",                        # Видео и стриминг (РФ)
    "rutubelist.ru",                    # Видео и стриминг (РФ)

    # === S ===
    "sber.ru",                          # Государственные, банковские и новостные ресурсы
    "sberbank.ru",                      # Государственные, банковские и новостные ресурсы
    "sbrf.ru",                          # Государственные, банковские и новостные ресурсы
    "sentry-saas.rambler-co.ru",        # Сборщик ошибок Рамблер
    "sentry.io",                        # Сборщик ошибок UI
    "sketchfab.com",                    # Системные CDN, библиотеки и медиа-инфраструктура
    "smartadserver.com",                # Инфраструктура стриминга и медиа-доставки Equativ
    "spot.im",                          # Платформа комментариев OpenWeb (бывший Spot.IM)
    "static.bbci.co.uk",                # Статика BBC
    "static.files.bbci.co.uk",          # Статика BBC

    # === T ===
    "t2.ru",                            # Экосистема Tele2
    "thetruestory.news",                # Новостные ресурсы
    "tildaapi.com",                     # Конструктор сайтов Tilda
    "tildacdn.com",                     # Конструктор сайтов Tilda
    "tinypass.com",                     # Инфраструктура подписок / Piano
    "twimg.com",                        # Экосистема X (Twitter)
    "twitter.com",                      # Экосистема X (Twitter)

    # === U ===
    "unpkg.com",                        # Глобальные CDN и служебная инфраструктура
    "userapi.com",                      # Системные CDN и библиотеки (VK)

    # === V ===
    "vdmsti.ru",                        # Служебное зеркало Ведомостей
    "vedomosti.ru",                     # Инфраструктура издания Ведомости
    "viafoura.co",                      # Платформа вовлечения аудитории Viafoura
    "viafoura.net",                     # CDN и служебные запросы Viafoura
    "vk-cdn.net",                       # Экосистема VK
    "vk-portal.net",                    # Экосистема VK
    "vk.com",                           # Экосистема VK
    "vk.me",                            # Экосистема VK
    "vk.ru",                            # Экосистема VK
    "vk.team",                          # Экосистема VK
    "vkcloud-storage.ru",               # Экосистема VK
    "vkuseraudio.net",                  # Экосистема VK
    "vkusernet.ru",                     # Инфраструктура авторизации VK / userapi
    "vkuserphoto.ru",                   # Экосистема VK
    "vkvd.net",                         # Экосистема VK
    "vkvideo.ru",                       # Экосистема VK

    # === W ===
    "wildberries.ru",                   # Ритейл
    "wistia.com",                       # Видеоплатформа Wistia для бизнеса

    # === X ===
    "x.com",                            # Экосистема X (Twitter)

    # === Y ===
    "yahoo.com",                        # Экосистема Yahoo (Авторизация и сервисы)
    "yahoo.net",                        # Служебная сеть Yahoo
    "yahoofinance.com",                 # Финансовый медиа-сервис Yahoo
    "yandexcloud.net",                  # Экосистема Яндекс
    "yapfiles.ru",                      # Легитимный пользовательский медиахостинг сайтов
    "yastatic-net.ru",                  # Экосистема Яндекс
    "yastatic.net",                     # Экосистема Яндекс
    "yimg.com",                         # CDN статики, картинок и почты Yahoo
    "youtube.com",                      # Видеохостинг
    "ytimg.com",                        # Изображения YouTube
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
    r"^adx\.videonow\.ru$",                          # Видео-реклама СМИ Videonow
    r"^sync\.videonow\.ru$",                         # Синхронизация Videonow
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

# --- Паттерны для детекции динамических хэш-поддоменов ---
_IS_HASH_PATTERNS = [
    re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),             # MD5 (Google safeframe и др.)
    re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-", re.IGNORECASE),  # Часть UUID
    re.compile(r"^\d{6,}$"),                                   # Чисто числовые ID от 6 знаков
]

# Кэшируем скомпилированные регулярные выражения
_COMPILED_BLACKLIST_PATTERNS = [re.compile(pat, re.IGNORECASE) for pat in STRICT_SUBDOMAINS_BLACKLIST_PATTERNS]

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
    """True, если домен (или его apex) явно попадает под STRICT_SUBDOMAINS_BLACKLIST_PATTERNS.
    Такие домены блокируются независимо от скоринга: у ad.mail.ru на странице mail.ru
    clean_score раздувается бонусом «тот же apex-домен», но это всё равно реклама."""
    domain = domain.lower().strip()
    apex = get_apex_domain(domain)
    return any(pat.search(domain) or (apex and pat.search(apex)) for pat in _COMPILED_BLACKLIST_PATTERNS)

def is_same_site(url, seed_apex):
    """True, если URL принадлежит сайту сида: тот же apex-домен (любой поддомен) или явно связанный из RELATED_APEXES."""
    apex = get_apex_domain(url)
    if not apex or not seed_apex:
        return False
    return apex == seed_apex or apex in RELATED_APEXES.get(seed_apex, ())

def should_block_domain(domain, page_apex=None, score=None):
    domain = domain.lower().strip()
    domain_apex = get_apex_domain(domain)
    
    # Если сам домен или его APEX (например, stbid.ru, casalemedia.com, ad.mail.ru) явно совпадает
    # с правилом из черного списка, блокируем БЕЗУСЛОВНО, не дожидаясь динамического скоринга.
    if is_hard_blacklisted(domain):
        return True
        
    # 1. ЖЕСТКИЙ ЧЕРНЫЙ СПИСОК (Регулярные выражения для текущего поддомена).
    # Проверяется ДО белого списка, иначе точечные правила (analytics.yahoo.com,
    # ssp.rambler.ru, px.hsmedia.ru ...) перекрываются белым списком корня.
    if any(pat.search(domain) for pat in _COMPILED_BLACKLIST_PATTERNS):
        return True

    # 2. ИСКЛЮЧЕНИЯ ДЛЯ ИНФРАСТРУКТУРЫ ПОИСКОВИКОВ
    if domain_apex and (domain_apex.startswith("google.") or domain_apex.startswith("yandex.")):
        if "tagmanager" in domain or "analytics" in domain: 
            return True
        return False

    # 3. ЕДИНЫЙ БЕЛЫЙ СПИСОК (инфраструктура + глобальный; домен или его поддомен).
    # Стоит ПОСЛЕ шага 2, чтобы google.com в списке не отключал блок tagmanager/analytics.
    if _in_list(domain, STRICT_DOMAINS_WHITELIST):
        return False

    # 4. ЗАЩИТА ОТ САМОБЛОКИРОВКИ
    if page_apex and (domain == page_apex or f"www.{domain}" == page_apex or domain_apex == page_apex): 
        return False
        
    # 5. ДИНАМИЧЕСКИЙ СКОРИНГ (С защитой от случайных срабатываний)
    if score is not None:
        ad_score = score.get("ad_score", 0)
        clean_score = score.get("clean_score", 0)
        
        # Если домен явно полезен (много системных ассетов), 
        # рекламный скор должен быть значительно выше для блокировки
        if clean_score > 0:
            return ad_score > (clean_score * 2) + 15  # Требуем уверенного перевеса
            
        # Если clean_score == 0, блокируем только при явном триггере,
        # а не из-за случайного "+6 за сторонний запрос"
        return ad_score >= 20 
        
    return True

# --- Сессионная классификация: агрегирование по страницам и группам «реплик» ---
_AD_HOST_LABEL_RE = re.compile(
    r"^(?:ads?|adx|adserver|adserv|adsrv|adtech|adnetwork|ssp|dsp|rtb|bid|bidder|prebid|pixel|px|sync|track|tracker|tracking|beacon)\d*$"
)

def host_ad_hint(domain):
    """True, если среди меток хоста (без TLD, с разбиением по дефису) есть рекламный термин: ads, ssp, dsp, rtb, px, sync ..."""
    labels = []
    for part in domain.lower().split(".")[:-1]:
        labels.extend(part.split("-"))
    return any(_AD_HOST_LABEL_RE.match(label) for label in labels)

def service_group_key(domain):
    """Ключ «одного сервиса»: реплики вида hal9000.x.net / hal90005.x.net, px2.x.pro / px4.x.pro, cs13.x.ru / cs2.x.ru
    получают общий ключ (первая метка без хвостовых цифр). У доменов 2-го уровня ключ — сам домен."""
    domain = domain.lower().strip()
    parts = domain.split(".")
    if len(parts) < 3:
        return domain
    stripped = re.sub(r"\d+$", "", parts[0]) or "#"
    return ".".join([stripped] + parts[1:])

def is_confident_ad(domain, score=None):
    """Строгий бан (идёт в hosts): явный чёрный список, нет данных скоринга (старые записи hosts),
    clean_score == 0 или ad_score > clean_score * STRICT_BAN_RATIO + STRICT_BAN_MARGIN."""
    if is_hard_blacklisted(domain):
        return True
    if not score:
        return True
    clean = score.get("clean_score", 0)
    ad = score.get("ad_score", 0)
    return clean == 0 or ad > clean * STRICT_BAN_RATIO + STRICT_BAN_MARGIN

def classify_session(domain_stats):
    """
    Единое решение по домену на основе очков со ВСЕХ страниц сессии (а не последней страницы).
    domain_stats: {domain: {"clean_score", "ad_score", "pages", "own_site"}}.
    Реплики одного сервиса (service_group_key) оцениваются по суммарным очкам группы;
    рекламный признак в имени хоста добавляет HOST_HINT_BONUS один раз на группу.
    Домен, который хотя бы раз был «своим» для сканируемой страницы (own_site), защищён от самоблокировки.
    Возвращает (ad_domains, clean_domains); в записях clean_score/ad_score — итоговые очки решения.
    """
    groups = {}
    for d in domain_stats:
        groups.setdefault(service_group_key(d), []).append(d)

    ad_domains, clean_domains = {}, {}
    for members in groups.values():
        clean = sum(domain_stats[m].get("clean_score", 0) for m in members)
        ad = sum(domain_stats[m].get("ad_score", 0) for m in members)
        own_site = any(domain_stats[m].get("own_site") for m in members)
        hint = any(host_ad_hint(m) for m in members)
        if hint:
            ad += HOST_HINT_BONUS
        for d in members:
            entry = {
                "clean_score": clean, "ad_score": ad,
                "pages": domain_stats[d].get("pages", 1),
                "group": len(members), "hint": hint,
            }
            page_apex = get_apex_domain(d) if own_site else None
            if should_block_domain(d, page_apex=page_apex, score=entry):
                ad_domains[d] = entry
            else:
                clean_domains[d] = entry
    return ad_domains, clean_domains

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
    Детектирует динамические хэш-поддомены и нормализует их до базового узла.
    Возвращает (is_dynamic, normalized_domain).
    """
    domain = domain.lower().strip()
    parts = domain.split('.')
    if len(parts) <= 2:
        # Если домен второго уровня (apex), ничего не схлопываем, чтобы не заблокировать корень
        return False, domain
        
    left_segment = parts[0]
    apex = get_apex_domain(domain)
    
    # --- СТРАТЕГИЯ 1: Защита крупных легитимных экосистем ---
    # (где корень блокировать НЕЛЬЗЯ, но нужно изолировать рекламные фреймы)
    if apex == "googlesyndication.com":
        return True, "safeframe.googlesyndication.com"
        
    if apex == "dzen.ru":
        for sub in ["cu.dzen.ru", "ms.dzen.ru"]:
            if sub in domain:
                return True, sub
        return False, domain  # Защищаем dzen.ru от полной блокировки

    # --- СТРАТЕГИЯ 2: Безусловное схлопывание для известных рекламных сетей ---
    # Если базовый домен (например, stbid.ru или adfox.ru) уже находится в черном списке,
    # любой его глубокий поддомен автоматически признается динамическим мусором и схлопывается до корня.
    if apex:
        if any(pat.search(apex) for pat in _COMPILED_BLACKLIST_PATTERNS):
            return True, apex

    # --- СТРАТЕГИЯ 3: Строгие паттерны для динамического мусора (универсальные ловушки) ---
    is_hash = _is_hash(left_segment)

    if is_hash and apex:
        return True, apex

    return False, domain

def sort_domains_by_level(domains):
    """Сортирует по apex-домену, внутри — по уровню вложенности, затем алфавитно."""
    def sort_key(d):
        apex = get_apex_domain(d) or d
        depth = len(d.split(".")) - len(apex.split("."))
        return (apex, depth, d)
    return sorted(domains, key=sort_key)
