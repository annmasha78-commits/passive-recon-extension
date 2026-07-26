// Guard against duplicate injection (content.js can be injected multiple times)
if (typeof window.__passiveReconLoaded === 'undefined') {
    window.__passiveReconLoaded = true;

    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "extractData") {
            // 1. Extract Emails - Improved Regex
            const emailRegex = /([a-zA-Z0-9._+-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,10})/gi;
            let emails = [];
            try {
                // Search both visible text and full HTML for attributes (like mailto:)
                const bodyText = document.body.innerText;
                const htmlText = document.documentElement.innerHTML;
                const matchesText = bodyText.match(emailRegex) || [];
                const matchesHtml = htmlText.match(emailRegex) || [];
                
                // Combine and filter out obvious false positives
                emails = [...matchesText, ...matchesHtml].filter(email => {
                    const lower = email.toLowerCase();
                    return !lower.endsWith('.png') && 
                           !lower.endsWith('.jpg') && 
                           !lower.endsWith('.jpeg') && 
                           !lower.endsWith('.gif') &&
                           !lower.endsWith('.webp') &&
                           !lower.endsWith('.svg');
                });
            } catch (e) {
                console.error("Email extraction failed:", e);
            }
            emails = [...new Set(emails.map(e => e.toLowerCase()))];

            // 1.5 Extract Phone Numbers
            let phones = [];
            try {
                // Find all tel: links
                const telLinks = Array.from(document.querySelectorAll('a[href^="tel:"]')).map(a => decodeURIComponent(a.href.replace('tel:', '')));
                
                // Find visible international numbers e.g., +1 234-567-8900
                const intlPhoneRegex = /(?:\+)[0-9]{1,3}[ .\-]?(?:\(0?\)[ .\-]?)?(?:[0-9]{1,4}[ .\-]?){2,4}[0-9]{3,4}/g;
                const matches = document.body.innerText.match(intlPhoneRegex) || [];
                
                phones = [...telLinks, ...matches].map(p => p.trim());
                // Filter out non-phone junk
                phones = phones.filter(p => p.length >= 7 && p.length <= 25 && /[0-9]{4}/.test(p));
                phones = [...new Set(phones)];
            } catch (e) {
                console.error("Phone extraction failed:", e);
            }

            // 2. Extract Links & Passive Vulnerability Checks
            const allLinks = Array.from(document.querySelectorAll('a[href], script[src], link[href]'));
            const currentHost = window.location.hostname;

            let internalLinks = [];
            let externalLinks = [];
            let pvi = [];

            allLinks.forEach(el => {
                try {
                    let href = el.href || el.src;
                    if (!href) return;

                    const lowerHref = href.toLowerCase();

                    // Expanded PVI Checks
                    if (lowerHref.includes('/.git/') || lowerHref.endsWith('/.git')) {
                        pvi.push({ name: 'Exposed .git directory linkage', severity: 'Critical', type: 'exposure', mitigation: 'Block access to .git folders in your web server configuration.' });
                    }
                    if (lowerHref.includes('/.env') || lowerHref.endsWith('.env')) {
                        pvi.push({ name: 'Exposed .env configuration file', severity: 'Critical', type: 'exposure', mitigation: 'Remove .env from the public web root or deny access via server config.' });
                    }
                    if (/\.(bak|sql|old|zip|tar|gz|config|php\.bak|php\.old)$/i.test(lowerHref)) {
                        pvi.push({ name: `Backup/Sensitive file exposed: ${href.split('/').pop()}`, severity: 'High', type: 'exposure', mitigation: 'Move backup files out of the public directory or restrict access.' });
                    }
                    if (lowerHref.includes('wp-config.php')) {
                        pvi.push({ name: 'WordPress config file reference found', severity: 'High', type: 'exposure', mitigation: 'Ensure wp-config.php permissions are restricted and not directly accessible.' });
                    }

                    // Outdated Libraries
                    if (el.tagName === 'SCRIPT' && lowerHref.includes('jquery')) {
                        if (/(1\.[0-9]+\.)|(2\.[0-1]\.)/.test(lowerHref)) {
                            pvi.push({ name: 'Potentially outdated jQuery (<3.0.0) detected', severity: 'Medium', type: 'outdated_lib', mitigation: 'Upgrade jQuery to a modern version (3.x) to patch known vulnerabilities.' });
                        }
                    }

                    // Categorize Links
                    if (el.tagName === 'A') {
                        const url = new URL(href);
                        if (url.hostname === currentHost || url.hostname.endsWith(`.${currentHost}`)) {
                            internalLinks.push(url.href);
                        } else if (url.protocol.startsWith('http')) {
                            externalLinks.push(url.href);
                        }
                    }
                } catch (e) {
                    // Handle relative paths or invalid URLs
                    const rawHref = el.getAttribute('href') || el.getAttribute('src');
                    if (rawHref && rawHref.startsWith('/')) {
                        internalLinks.push(window.location.origin + rawHref);
                    }
                }
            });

            internalLinks = [...new Set(internalLinks)];
            externalLinks = [...new Set(externalLinks)];
            pvi = pvi.filter((v, i, a) => a.findIndex(t => (t.name === v.name)) === i);

            // 3. Expanded & Robust Tech Stack Detection
            let tech = [];
            try {
                const htmlText = document.documentElement.innerHTML.toLowerCase();
                const scriptSrcs = Array.from(document.querySelectorAll('script[src]')).map(s => s.src.toLowerCase());
                const linkHrefs = Array.from(document.querySelectorAll('link[href]')).map(l => l.href.toLowerCase());
                const allSources = [...scriptSrcs, ...linkHrefs].join(' ');

                // ── CMS ──
                if (htmlText.includes('wp-content') || htmlText.includes('wp-includes') || htmlText.includes('wp-json')) tech.push('WordPress');
                if (htmlText.includes('sites/default/files') || htmlText.includes('drupal.js') || htmlText.includes('drupal.settings')) tech.push('Drupal');
                if (htmlText.includes('joomla') || htmlText.includes('/components/com_')) tech.push('Joomla');
                if (htmlText.includes('squarespace') || htmlText.includes('static.squarespace.com')) tech.push('Squarespace');
                if (htmlText.includes('wix.com') || htmlText.includes('static.wixstatic.com')) tech.push('Wix');
                if (htmlText.includes('webflow.com') || htmlText.includes('assets.website-files.com')) tech.push('Webflow');
                if (htmlText.includes('ghost.io') || htmlText.includes('ghost/') || (document.querySelector('meta[name="generator"]') || {}).content?.toLowerCase().includes('ghost')) tech.push('Ghost');
                if (htmlText.includes('shopify.com') || htmlText.includes('cdn.shopify.com') || htmlText.includes('shopify-section')) tech.push('Shopify');
                if (htmlText.includes('magento') || htmlText.includes('mage/')) tech.push('Magento');
                if (htmlText.includes('prestashop') || htmlText.includes('/modules/prestashop')) tech.push('PrestaShop');
                if (htmlText.includes('opencart') || htmlText.includes('/catalog/view/theme/')) tech.push('OpenCart');
                if (htmlText.includes('bigcommerce.com') || htmlText.includes('cdn11.bigcommerce.com')) tech.push('BigCommerce');

                // ── JS Frameworks ──
                if (htmlText.includes('react') && (htmlText.includes('_reactroot') || htmlText.includes('react-root') || htmlText.includes('__reactfibr') || htmlText.includes('data-reactroot') || htmlText.includes('react.production.min') || htmlText.includes('react.development'))) tech.push('React');
                if (htmlText.includes('vue') && (htmlText.includes('v-bind') || htmlText.includes('v-for') || htmlText.includes('data-v-') || htmlText.includes('__vue') || htmlText.includes('vue.min.js') || htmlText.includes('vue.runtime'))) tech.push('Vue.js');
                if (htmlText.includes('angular') && (htmlText.includes('ng-version') || htmlText.includes('ng-app') || htmlText.includes('ng-controller') || htmlText.includes('angular.min.js') || allSources.includes('angular'))) tech.push('Angular');
                if (htmlText.includes('svelte') || allSources.includes('svelte')) tech.push('Svelte');
                if (htmlText.includes('ember') && (allSources.includes('ember.min.js') || allSources.includes('ember.prod.js'))) tech.push('Ember.js');
                if (allSources.includes('backbone.min.js') || allSources.includes('backbone.js')) tech.push('Backbone.js');
                if (allSources.includes('alpinejs') || htmlText.includes('x-data=') || htmlText.includes('x-bind=')) tech.push('Alpine.js');
                if (htmlText.includes('htmx') || allSources.includes('htmx.min.js')) tech.push('HTMX');

                // ── Metaframeworks ──
                if (htmlText.includes('_next/static') || htmlText.includes('__next') || htmlText.includes('next.js') || window.__NEXT_DATA__) tech.push('Next.js');
                if (htmlText.includes('__nuxt') || htmlText.includes('_nuxt/') || window.__nuxt) tech.push('Nuxt.js');
                if (htmlText.includes('gatsby') || htmlText.includes('___gatsby') || allSources.includes('gatsby')) tech.push('Gatsby');
                if (htmlText.includes('astro') && (allSources.includes('astro') || htmlText.includes('astro-island'))) tech.push('Astro');
                if (htmlText.includes('remix') && htmlText.includes('__remixContext')) tech.push('Remix');
                if (htmlText.includes('sveltekit') || htmlText.includes('__svelte') || htmlText.includes('/_app/immutable/')) tech.push('SvelteKit');

                // ── CSS Frameworks ──
                if (allSources.includes('bootstrap') || htmlText.includes('bootstrap.min.css') || htmlText.includes('bootstrap.bundle') || document.querySelector('[class*="col-md-"],[class*="col-lg-"],[class*="container-fluid"]')) tech.push('Bootstrap');
                if (allSources.includes('tailwind') || htmlText.includes('tailwindcss') || document.querySelector('[class*="flex-"],[class*="text-xl"],[class*="bg-gray"]')) tech.push('TailwindCSS');
                if (allSources.includes('bulma') || htmlText.includes('bulma.min.css')) tech.push('Bulma');
                if (allSources.includes('foundation') || htmlText.includes('foundation.min.css')) tech.push('Foundation');
                if (allSources.includes('materialize') || htmlText.includes('materialize.min.css')) tech.push('Materialize CSS');
                if (allSources.includes('semantic.min.js') || allSources.includes('semantic-ui')) tech.push('Semantic UI');
                if (allSources.includes('mui') || htmlText.includes('muicss')) tech.push('MUI/Material UI');
                if (allSources.includes('chakra-ui') || htmlText.includes('chakra')) tech.push('Chakra UI');

                // ── Libraries ──
                if (allSources.includes('jquery') || htmlText.includes('jquery.min.js') || htmlText.includes('jquery-') || window.jQuery) tech.push('jQuery');
                if (allSources.includes('lodash') || window._?.VERSION) tech.push('Lodash');
                if (allSources.includes('moment.min.js') || allSources.includes('moment.js')) tech.push('Moment.js');
                if (allSources.includes('axios.min.js') || allSources.includes('axios.js')) tech.push('Axios');
                if (allSources.includes('gsap.min.js') || allSources.includes('gsap.js') || window.gsap) tech.push('GSAP');
                if (allSources.includes('three.min.js') || allSources.includes('three.js') || window.THREE) tech.push('Three.js');
                if (allSources.includes('d3.min.js') || allSources.includes('d3.js') || window.d3) tech.push('D3.js');
                if (allSources.includes('chart.js') || allSources.includes('chart.min.js') || window.Chart) tech.push('Chart.js');
                if (allSources.includes('socket.io') || window.io?.sockets) tech.push('Socket.IO');

                // ── Backend/Server Hints ──
                if (htmlText.includes('php') && (htmlText.includes('.php') || htmlText.includes('x-powered-by: php'))) tech.push('PHP');
                if (htmlText.includes('laravel') || htmlText.includes('csrf-token') && htmlText.includes('laravel')) tech.push('Laravel');
                if (htmlText.includes('django') || htmlText.includes('csrfmiddlewaretoken')) tech.push('Django');
                if (htmlText.includes('rails') || htmlText.includes('data-turbolinks') || htmlText.includes('authenticity_token')) tech.push('Ruby on Rails');
                if (htmlText.includes('asp.net') || htmlText.includes('__viewstate') || htmlText.includes('__dopostback')) tech.push('ASP.NET');
                if (htmlText.includes('express') && htmlText.includes('node')) tech.push('Node.js/Express (hint)');

                // ── Analytics & Marketing ──
                if (htmlText.includes('google-analytics.com') || htmlText.includes('ga.js') || htmlText.includes('gtag(') || htmlText.includes('analytics.js')) tech.push('Google Analytics');
                if (htmlText.includes('googletagmanager.com') || htmlText.includes('gtm.js')) tech.push('Google Tag Manager');
                if (htmlText.includes('facebook.net/en_US/fbevents') || htmlText.includes('fbq(')) tech.push('Facebook Pixel');
                if (htmlText.includes('hotjar.com') || htmlText.includes('hjBootstrap')) tech.push('Hotjar');
                if (htmlText.includes('intercom.io') || htmlText.includes('intercomSettings')) tech.push('Intercom');
                if (htmlText.includes('segment.com') || htmlText.includes('analytics.identify(')) tech.push('Segment');
                if (htmlText.includes('mixpanel.com') || window.mixpanel) tech.push('Mixpanel');
                if (htmlText.includes('hubspot.com') || htmlText.includes('hs-scripts.com') || htmlText.includes('hscta')) tech.push('HubSpot');
                if (htmlText.includes('heap.io') || window.heap) tech.push('Heap Analytics');

                // ── CDN & Infrastructure ──
                if (htmlText.includes('__cfduid') || htmlText.includes('cloudflare') || htmlText.includes('__cf_bm')) tech.push('Cloudflare');
                if (htmlText.includes('fastly.net') || allSources.includes('fastly')) tech.push('Fastly CDN');
                if (htmlText.includes('akamai') || allSources.includes('akamaized.net')) tech.push('Akamai CDN');
                if (allSources.includes('jsdelivr.net')) tech.push('jsDelivr CDN');
                if (allSources.includes('cdnjs.cloudflare.com')) tech.push('cdnjs CDN');
                if (allSources.includes('unpkg.com')) tech.push('unpkg CDN');

                // ── Payments ──
                if (htmlText.includes('stripe.com/v3') || htmlText.includes('js.stripe.com') || window.Stripe) tech.push('Stripe');
                if (htmlText.includes('paypal.com') || htmlText.includes('paypalobjects.com')) tech.push('PayPal');
                if (htmlText.includes('braintreegateway.com') || window.braintree) tech.push('Braintree');

                // ── Web3 / Crypto ──
                if (htmlText.includes('metamask') || htmlText.includes('web3.js') || htmlText.includes('ethers.js') || window.ethereum || window.web3) tech.push('Web3 / Crypto');

                // ── Generator meta tag ──
                const generator = document.querySelector('meta[name="generator"]');
                if (generator && generator.content) {
                    const genContent = generator.content.trim();
                    // Avoid duplicating what we already found
                    const alreadyDetected = tech.some(t => genContent.toLowerCase().includes(t.toLowerCase()));
                    if (!alreadyDetected) {
                        tech.push(`Generator: ${genContent}`);
                    }
                }

                // ── Runtime window checks ──
                if (window.next && !tech.includes('Next.js')) tech.push('Next.js (Runtime)');
                if (window.Nuxt && !tech.includes('Nuxt.js')) tech.push('Nuxt.js (Runtime)');
                if (window.React && !tech.includes('React')) tech.push('React (Runtime)');
                if (window.Vue && !tech.includes('Vue.js')) tech.push('Vue.js (Runtime)');
                if (window.angular && !tech.includes('Angular')) tech.push('Angular (Runtime)');

            } catch (e) {
                console.error("Tech detection failed:", e);
            }

            tech = [...new Set(tech)];

            sendResponse({
                internalLinks,
                externalLinks,
                emails,
                phones,
                technologies: tech,
                pvi
            });

            return true; // Keep channel open for async if needed
        }
    });
}
