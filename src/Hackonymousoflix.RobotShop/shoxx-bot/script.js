// ShoxxBot — simule l'administrateur du RobotShop.
// Il consulte régulièrement la page /read.php (qui affiche les messages reçus)
// en portant le cookie d'administration. Si un message contient un XSS,
// celui-ci s'exécute dans son navigateur (faiblesse volontaire du challenge).
//
// À l'origine ce bot était écrit avec casperjs/PhantomJS (désormais obsolète),
// on le réimplémente ici avec Puppeteer (headless Chrome) tout en conservant
// le comportement exact qui rend l'épreuve 12 exploitable.

const puppeteer = require('puppeteer');

const host = 'robotshop';
const url = 'http://' + host + '/read.php';
const timeout = 3000;
const repeatcount = Math.floor((7 * 24 * 3600) / timeout); // une semaine de tentatives, puis restart

(async () => {
    const browser = await puppeteer.launch({
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors']
    });

    const page = await browser.newPage();

    // Cookie d'administration (identique à l'original)
    await page.setCookie({
        name: 'adminCookie',
        value: 'SGVsbG8sIGMnZXN0IFJlbWksIGFuY2llbiBkZSBsYSB0ZWFtIHNlY3UK',
        domain: host,
        path: '/',
        httpOnly: false
    });

    for (let i = 0; i < repeatcount; i++) {
        try {
            await page.goto(url, { waitUntil: 'load', timeout: 10000 });

            const str = await page.evaluate(() => document.body.innerHTML.trim());
            if (str) {
                console.log(str);
            }
        } catch (e) {
            console.log('Unable to load resource: ' + e.message);
        }

        await new Promise((resolve) => setTimeout(resolve, timeout));
    }

    await browser.close();
})();