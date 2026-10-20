// ShoxxBot — simulates the RobotShop administrator.
// It regularly visits /read.php (which displays the messages it received)
// while carrying the admin cookie. If a message contains an XSS payload, it
// executes in its browser (an intentional weakness of the challenge).
//
// This bot was originally written with casperjs/PhantomJS (now obsolete); it
// is reimplemented here with Puppeteer (headless Chrome) while keeping the
// exact behavior that makes challenge 12 exploitable.

const puppeteer = require('puppeteer');

const host = 'robotshop';
const url = 'http://' + host + '/read.php';
const timeout = 3000;
const repeatcount = Math.floor((7 * 24 * 3600) / timeout); // one week of attempts, then restart

(async () => {
    const browser = await puppeteer.launch({
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--ignore-certificate-errors']
    });

    const page = await browser.newPage();

    // Admin cookie (identical to the original)
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