import { parse as parseDomain } from '../../shared/tldts.js';
import { filenameExtension,urlFileExtension } from '../url/download-file-extension.js';
const U='unknown';
const site=url=>{try{return parseDomain(new URL(url).hostname,{allowPrivateDomains:true}).domain||null;}catch{return null;}};

export function analyzeDomDownloadLinks(frames,incomplete=false){
  const observed=frames.filter(frame=>Array.isArray(frame.download_page?.links));
  const partial=incomplete||observed.length!==frames.length||observed.some(frame=>frame.download_page.truncated||frame.download_page.unresolved_controls>0);
  const links=observed.flatMap(frame=>frame.download_page.links.map(link=>{
    let target=null,extension=null;
    try{const u=new URL(link.url,frame.page_origin);if(['http:','https:','blob:'].includes(u.protocol)){u.username='';u.password='';u.search='';u.hash='';target=u.href;extension=filenameExtension(link.filename_hint)||urlFileExtension(target);}}catch{}
    const from=site(frame.page_origin),to=site(target);
    return {url:target,text:String(link.text||'').slice(0,160),filename_hint:link.filename_hint||null,
      extension:extension||U,
      cross_domain:from&&to?from!==to:U,source_domain:from,target_domain:to};
  }));
  const available=observed.length>0;
  return {has_download_link:links.length?true:!available||partial?U:false,
    download_file_extensions:available?[...new Set(links.map(link=>link.extension))]:null,
    download_target_cross_domain:links.some(link=>link.cross_domain===true)?true:
      !available||partial||links.some(link=>link.cross_domain===U)?U:false,
    download_links:links.slice(0,60),
    download_unresolved_checks:[!available?'download_links_not_recorded':partial?'download_scan_incomplete':null].filter(Boolean),
    download_scope:'dom_links_only'};
}
