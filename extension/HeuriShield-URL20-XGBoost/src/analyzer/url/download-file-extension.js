// Supplemental URL metadata only; never part of the frozen 20-feature model vector.
// Files that run code when opened, plus archive/disk-image/shortcut containers
// commonly used to deliver them (zip, iso, lnk, hta, ...). Manual configuration.
export const RUNNABLE_FILE_EXTENSIONS=['exe','msi','msix','appx','apk','scr','com','bat','cmd','ps1','vbs','vbe','js','jse','wsf','hta','lnk','msc','xll','jar','dmg','pkg','deb','rpm'];
export const CONTAINER_FILE_EXTENSIONS=['zip','rar','7z','iso','img','vhd','vhdx','cab'];
export const EXECUTABLE_FILE_EXTENSIONS=new Set([...RUNNABLE_FILE_EXTENSIONS,...CONTAINER_FILE_EXTENSIONS]);
export function filenameExtension(value){
  const name=String(value||'').split(/[\\/]/).at(-1).trim().toLowerCase();
  const dot=name.lastIndexOf('.');
  const extension=dot>=0?name.slice(dot+1):'';
  return /^[a-z0-9]{1,12}$/.test(extension)?extension:null;
}
export function urlFileExtension(value){
  try{
    const url=new URL(value);
    if(!['http:','https:','blob:'].includes(url.protocol))return 'unknown';
    // Query/fragment names are not evidence of the file offered by this URL.
    return filenameExtension(decodeURIComponent(url.pathname));
  }catch{return 'unknown';}
}
export function executableExtensionEvidence(extensions,{incomplete=false}={}){
  if(!Array.isArray(extensions))return 'unknown';
  if(extensions.some(extension=>EXECUTABLE_FILE_EXTENSIONS.has(extension)))return true;
  return incomplete||extensions.includes('unknown')?'unknown':false;
}
