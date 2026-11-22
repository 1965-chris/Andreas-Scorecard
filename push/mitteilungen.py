# Mitteilungen der Minigolf-Scorecard – schickt Push-Mitteilungen an die Geräte, die sie erlaubt haben.
# Diese Datei legt die App selbst ins Repo (push/mitteilungen.py) und hält sie aktuell;
# gestartet wird sie von .github/workflows/mitteilungen.yml, sobald sich minigolf-nachrichten.json ändert.
# Gemeldet wird jede neue Nachricht den Geräten des Empfängers (Feld 'an').
# Steht dort nichts, geht sie an alle angemeldeten Geräte ausser denen des Absenders.
# Der geheime Schlüssel liegt nur als GitHub-Secret PUSH_SCHLUESSEL vor, nie im Repo.
MITTEILUNGEN_VERSION = 2
import base64, hashlib, hmac, json, os, time, urllib.error, urllib.request
from urllib.parse import urlparse

FRISCH = 3 * 86400                  # ältere Nachrichten nicht mehr melden (z. B. nach verlorenem Stand)
NACHRICHTEN_DATEI = 'minigolf-nachrichten.json'
STAND_DATEI = 'push/stand.json'
HOECHSTENS = 5                      # mehr als so viele auf einmal werden zusammengefasst


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64u(s):
    s = str(s).strip()
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# ---------- Web Push: Verschlüsselung (RFC 8291) und Absender-Ausweis (VAPID, RFC 8292) ----------
def _hkdf(salz, ikm, info, laenge):
    prk = hmac.new(salz, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b'\x01', hashlib.sha256).digest()[:laenge]


def schluessel_laden(text):
    from cryptography.hazmat.primitives.asymmetric import ec
    roh = unb64u(text)
    if len(roh) != 32: raise ValueError('Der Schlüssel hat nicht die richtige Länge.')
    return ec.derive_private_key(int.from_bytes(roh, 'big'), ec.SECP256R1())


def oeffentlich_roh(privat):
    from cryptography.hazmat.primitives import serialization
    return privat.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def verschluesseln(nutzlast, p256dh, auth, _salz=None, _privat=None):
    """Inhalt für genau ein Gerät verschlüsseln (aes128gcm, ein Datensatz)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ua_public, auth_secret = unb64u(p256dh), unb64u(auth)
    as_privat = _privat or ec.generate_private_key(ec.SECP256R1())
    as_public = oeffentlich_roh(as_privat)
    geraet = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    ecdh = as_privat.exchange(ec.ECDH(), geraet)
    ikm = _hkdf(auth_secret, ecdh, b'WebPush: info\x00' + ua_public + as_public, 32)
    salz = _salz or os.urandom(16)
    cek = _hkdf(salz, ikm, b'Content-Encoding: aes128gcm\x00', 16)
    nonce = _hkdf(salz, ikm, b'Content-Encoding: nonce\x00', 12)
    geheim = AESGCM(cek).encrypt(nonce, nutzlast + b'\x02', None)
    return salz + (4096).to_bytes(4, 'big') + bytes([len(as_public)]) + as_public + geheim


def vapid(endpunkt, privat, absender, jetzt=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    u = urlparse(endpunkt)
    kopf = b64u(json.dumps({'typ': 'JWT', 'alg': 'ES256'}, separators=(',', ':')).encode())
    inhalt = b64u(json.dumps({'aud': f'{u.scheme}://{u.netloc}', 'exp': int(jetzt or time.time()) + 12 * 3600,
                              'sub': absender}, separators=(',', ':')).encode())
    r, s = decode_dss_signature(privat.sign(f'{kopf}.{inhalt}'.encode(), ec.ECDSA(hashes.SHA256())))
    return f'vapid t={kopf}.{inhalt}.{b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}, k={b64u(oeffentlich_roh(privat))}'


def senden(abo, daten, privat, absender):
    """Eine Mitteilung an ein Gerät. Antwort: HTTP-Code (201 = angenommen, 404/410 = Gerät hat abbestellt)."""
    koerper = verschluesseln(json.dumps(daten, ensure_ascii=False).encode(), abo['p256dh'], abo['auth'])
    req = urllib.request.Request(abo['endpoint'], data=koerper, method='POST', headers={
        'TTL': '86400', 'Urgency': 'normal', 'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        'Authorization': vapid(abo['endpoint'], privat, absender)})
    try:
        with urllib.request.urlopen(req, timeout=20) as r: return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


# ---------- GitHub ----------
REPO = os.environ.get('GITHUB_REPOSITORY', '')
ZWEIG = os.environ.get('GITHUB_REF_NAME', 'main')
TOKEN = os.environ.get('GH_TOKEN', '')
API = os.environ.get('GITHUB_API_URL', 'https://api.github.com')


def gh(methode, pfad, daten=None, roh=False):
    req = urllib.request.Request(f'{API}/repos/{REPO}{pfad}', method=methode,
        data=None if daten is None else json.dumps(daten).encode(),
        headers={'Authorization': 'Bearer ' + TOKEN,
                 'Accept': 'application/vnd.github.raw' if roh else 'application/vnd.github+json',
                 'Content-Type': 'application/json', 'User-Agent': 'Minigolf-Mitteilungen'})
    for versuch in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                b = r.read()
                return b if roh else json.loads(b or b'null')
        except urllib.error.HTTPError as e:
            if e.code == 404 and methode == 'GET': return None
            if e.code in (409, 422, 500, 502, 503) and versuch < 3: time.sleep(2 + 2 * versuch); continue
            raise


def json_lesen(pfad):
    b = gh('GET', f'/contents/{pfad}?ref={ZWEIG}', roh=True)
    if b is None: return None
    try: return json.loads(b.decode('utf-8'))
    except Exception: return None


def schreiben(pfad, daten, nachricht):
    alt = gh('GET', f'/contents/{pfad}?ref={ZWEIG}')
    gh('PUT', f'/contents/{pfad}', {'message': nachricht, 'branch': ZWEIG,
        'content': base64.b64encode(json.dumps(daten, ensure_ascii=False, indent=1).encode()).decode(),
        **({'sha': alt['sha']} if alt else {})})


# ---------- Minigolf ----------
def kurz(text, n=140):
    t = ' '.join(str(text or '').split())
    return t if len(t) <= n else t[:n - 1].rstrip() + '…'


def abo_ok(a, schluessel):
    """Nur Geräte mit vollständigen Angaben und zum aktuellen Schlüssel."""
    return bool(a and a.get('endpoint') and a.get('p256dh') and a.get('auth')
                and (not schluessel or not a.get('schluessel') or a.get('schluessel') == schluessel))


def gleich(a, b):
    return str(a or '').strip().lower() == str(b or '').strip().lower()


def fuer_wen(abos, absender, empfaenger=None):
    """Die Geräte des Empfängers. Ohne Empfänger: alle ausser denen des Absenders."""
    if empfaenger:
        return [a for a in abos if gleich(a.get('name'), empfaenger) and not gleich(a.get('name'), absender)]
    return [a for a in abos if not gleich(a.get('name'), absender)]


def main():
    privat_text = os.environ.get('PUSH_SCHLUESSEL', '').strip()
    if not privat_text:
        print('Kein PUSH_SCHLUESSEL hinterlegt – es wird nichts verschickt.'); return
    daten = json_lesen(NACHRICHTEN_DATEI) or {}
    nachrichten = [n for n in (daten.get('items') or []) if isinstance(n, dict) and n.get('id')]
    abos_roh = [a for a in (daten.get('abos') or []) if isinstance(a, dict)]
    if not nachrichten or not abos_roh:
        print('Nichts zu melden (%d Nachrichten, %d Geräte).' % (len(nachrichten), len(abos_roh))); return

    privat = schluessel_laden(privat_text)
    oeffentlich = b64u(oeffentlich_roh(privat))
    abos = [a for a in abos_roh if abo_ok(a, oeffentlich)]
    if not abos:
        print('Kein Gerät passt zum hinterlegten Schlüssel.'); return

    stand = json_lesen(STAND_DATEI) or {}
    gemeldet = set(stand.get('gemeldet') or [])
    jetzt = time.time()

    neu = []
    for n in nachrichten:
        if n['id'] in gemeldet: continue
        at = n.get('at') or 0
        if at and at / 1000.0 < jetzt - FRISCH:        # alte Nachricht, nur vermerken
            gemeldet.add(n['id']); continue
        neu.append(n)
    if not neu:
        print('Keine neuen Nachrichten.')
        if set(stand.get('gemeldet') or []) != gemeldet:
            schreiben(STAND_DATEI, {'gemeldet': sorted(gemeldet)[-500:]}, 'Mitteilungen: Stand')
        return

    # Nach Absender und Empfänger zusammenfassen: Jeder Faden meldet sich einzeln,
    # und mehrere Nachrichten darin ploppen nicht fünfmal hintereinander auf.
    nach_absender = {}
    for n in neu:
        kennung = (str(n.get('from') or 'Mitspieler'), str(n.get('an') or ''))
        nach_absender.setdefault(kennung, []).append(n)

    weg = set()
    verschickt = 0
    for (absender, empfaenger), liste in nach_absender.items():
        ziele = fuer_wen(abos, absender, empfaenger)
        if not ziele:
            for n in liste: gemeldet.add(n['id'])
            continue
        liste.sort(key=lambda x: x.get('at') or 0)
        if len(liste) == 1:
            text = kurz(liste[0].get('text'))
        else:
            text = '%d neue Nachrichten · %s' % (len(liste), kurz(liste[-1].get('text'), 90))
        inhalt = {'titel': '⛳ ' + absender, 'text': text, 'tag': 'minigolf-' + absender, 'ziel': 'nachrichten'}
        for a in ziele:
            code = senden(a, inhalt, privat, 'mailto:minigolf@example.invalid')
            if code in (404, 410): weg.add(a.get('endpoint'))
            elif 200 <= code < 300: verschickt += 1
            print('%s %s -> %s' % (absender, (a.get('name') or '?'), code))
        for n in liste: gemeldet.add(n['id'])

    schreiben(STAND_DATEI, {'gemeldet': sorted(gemeldet)[-500:], 'stand': int(jetzt)}, 'Mitteilungen: Stand')

    if weg:   # Geräte, die abbestellt haben, aus der Liste nehmen
        rest = [a for a in abos_roh if a.get('endpoint') not in weg]
        if len(rest) != len(abos_roh):
            daten_jetzt = json_lesen(NACHRICHTEN_DATEI) or {}
            daten_jetzt['abos'] = [a for a in (daten_jetzt.get('abos') or []) if a.get('endpoint') not in weg]
            schreiben(NACHRICHTEN_DATEI, daten_jetzt, 'Mitteilungen: abgemeldete Geräte entfernt')
    print('Fertig: %d Mitteilungen verschickt, %d Geräte entfernt.' % (verschickt, len(weg)))


if __name__ == '__main__':
    main()
