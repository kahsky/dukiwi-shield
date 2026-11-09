"""Link Guard: brands that are everyday words (2.9.9).

"admin" is the brand key of admin.ch (Swiss federal administration): the administration area of any web site
("https://chatillon-broye.ch/admin/login") was blocked as "login page of a brand hosted on another domain", and so
were admin.mysite.ch, admin.fr… The brand in a path was also matched inside words ("/pineapple" → Apple).

- everyday-word brands: only the strong signs (real domain at the start of another host, replaced characters,
  admin-ch style combinations);
- brand in a path: whole words only;
- real imitations of the other brands unchanged.
"""
import _harness as h

R = h.Results("Link Guard brands that are everyday words")
u = h.load("dukiwi_shield_urlguard.py", "dukiwi_shield_urlguard_under_test")


def reasons(url):
    return u.analyze(url)[0]


clean = ["https://chatillon-broye.ch/admin/login", "https://admin.chatillon-broye.ch/login", "https://admin-panel.example.com/",
         "https://admin.fr/login", "https://shop.ch/pineapple/login", "https://www.admin.ch/login",
         "https://myshop.ch/orange/login", "https://steam.example.org/login"]
bad = {name: reasons(name) for name in clean if reasons(name)}
R.check("the admin area of one's own site and everyday words are not brand imitations", not bad, bad)

kept = {"https://admin.ch.evil.ru/login": "brand_domain_prefix", "https://admin-ch.com/login": "brand_combo",
        "https://0utlook.com/": "homoglyph", "https://evil.net/paypal/login": "brand_in_path",
        "https://paypal.evil.com/": "brand_in_subdomain", "https://paypal.xyz/": "brand_other_tld",
        "https://amazom.com/": "typosquat", "https://evil.net/x/paypal-login": "brand_in_path"}
missed = {url: reasons(url) for url, want in kept.items() if want not in reasons(url)}
R.check("real imitations still caught (admin.ch prefix, admin-ch, 0utlook, PayPal path / subdomain / TLD, typo)",
        not missed, missed)
R.done()
