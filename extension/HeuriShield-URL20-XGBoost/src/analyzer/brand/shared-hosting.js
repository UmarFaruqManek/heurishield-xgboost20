/*
 * Platform hosting bersama yang memberi subdomain kepada pengguna (penyewa).
 * Subdomain penyewa bukan milik brand platform, sehingga kecocokan domain
 * brand platform pada subdomain tersebut tidak dapat dipastikan (unknown).
 * Daftar ini konfigurasi manual, bukan hasil pelatihan. Hanya registrable domain.
 */
export const SHARED_HOSTING_ROOTS = new Set([
  // Ditambahkan dari audit v0.7.0 (penyewa yang teramati pada data phishing).
  "contaboserver.net", "craftum.io", "edgeone.dev",
  "000webhostapp.com", "42web.io", "adalo.com", "afraid.org",
  "amazonaws.com", "amplifyapp.com", "anvil.app", "appspot.com",
  "atlassian.net", "awardspace.info", "azurestaticapps.net", "azurewebsites.net",
  "bigcommerce.com", "blogspot.com", "bubbleapps.io", "byethost.com",
  "carrd.co", "chickenkiller.com", "cloudapp.net", "cloudfront.net",
  "cloudfunctions.net", "codepen.io", "codesandbox.io", "csb.app",
  "ddns.net", "deepnote.com", "deno.dev", "deno.net",
  "devtunnels.ms", "dnsalias.com", "dnsalias.net", "dnsalias.org",
  "docs.page", "docusaurus.io", "duckdns.org", "dynu.net",
  "dynv6.net", "ecwid.com", "elasticbeanstalk.com", "epizy.com",
  "firebaseapp.com", "firebaseio.com", "fly.dev", "framer.app",
  "framer.website", "freeddns.org", "freehostia.com", "freshdesk.com",
  "freshservice.com", "gitbook.com", "gitbook.io", "github.io",
  "gitlab.io", "glide.page", "glideapp.io", "glitch.me",
  "googlepages.com", "googleusercontent.com", "gradio.live", "great-site.net",
  "gumroad.com", "helpscoutdocs.com", "herokuapp.com", "hf.space",
  "hopto.org", "hubspotpagebuilder.com", "hubspotpagebuilder.eu", "hubspotusercontent.com",
  "huggingface.co", "ignorelist.com", "infinityfreeapp.com", "intercom.help",
  "jimdofree.com", "jimdosite.com", "jsfiddle.net", "koyeb.app",
  "lhr.life", "loca.lt", "localhost.run", "localtunnel.me",
  "mkdocs.io", "mooo.com", "mybigcommerce.com", "myddns.me",
  "myftp.org", "myshopify.com", "mystrikingly.com", "myvnc.com",
  "neocities.org", "netlify.app", "ngrok-free.app", "ngrok.app",
  "ngrok.io", "no-ip.org", "notion.site", "notion.so",
  "now.sh", "observablehq.com", "onrender.com", "pages.dev",
  "pinggy.io", "pinggy.link", "pythonanywhere.com", "r2.dev",
  "railway.app", "readthedocs.io", "readthedocs.org", "readymag.com",
  "redirectme.net", "repl.co", "replit.app", "rf.gd",
  "run.app", "sellfy.store", "serveblog.net", "serveftp.com",
  "servegame.com", "servehttp.com", "serveo.net", "shopify.com",
  "site123.com", "site123.me", "softr.app", "square.site",
  "squarespace.com", "stackblitz.io", "statuspage.io", "streamlit.app",
  "streamlit.io", "supabase.co", "supabase.in", "surge.sh",
  "sytes.net", "tilda.cc", "tilda.ws", "trafficmanager.net",
  "trycloudflare.com", "tunnelto.dev", "typedream.app", "ucraft.site",
  "us.to", "vercel.app", "web.app", "webador.co.uk",
  "webador.com", "webcontainer.io", "webflow.io", "webhop.me",
  "webnode.com", "webnode.page", "weebly.com", "wixsite.com",
  "wixstudio.io", "wordpress.com", "workers.dev", "wpcomstaging.com",
  "wpengine.com", "wpenginepowered.com", "zapto.org", "zeit.sh",
  "zendesk.com"
]);

/** True when hostname is a tenant subdomain of a shared hosting root (not the root or www). */
export function isSharedHostingTenant(hostname, registrableDomain) {
  const host = String(hostname || "").toLowerCase().replace(/\.$/, "");
  const root = String(registrableDomain || "").toLowerCase();
  return SHARED_HOSTING_ROOTS.has(root) && host !== root && host !== `www.${root}` && host.endsWith(`.${root}`);
}
