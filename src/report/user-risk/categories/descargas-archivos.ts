import {
  hasDetail,
  makeItem,
  type UserRiskCategoryEvaluator,
  type UserRiskStaticRule,
} from '../types.js';

const DOWNLOAD_API_RE =
  /chrome\.downloads\.download|chrome\.downloads\.open|chrome\.downloads\.erase|chrome\.downloads\.removeFile|chrome\.downloads\.show/i;
const DOWNLOAD_EVENT_RE =
  /chrome\.downloads\.onCreated|chrome\.downloads\.onChanged|chrome\.downloads\.onDeterminingFilename/i;
const FS_ACCESS_RE =
  /showSaveFilePicker|showOpenFilePicker|showDirectoryPicker|FileSystemFileHandle|FileSystemDirectoryHandle|webkitDirectory|chrome\.fileSystem/i;
const BLOB_RE =
  /new Blob\(|URL\.createObjectURL|application\/octet-stream|application\/x-msdownload|application\/x-msi/i;
const EXEC_EXT_RE =
  /\.exe(?:['"\s/?#&)]|$)|\.msi\b|\.dmg\b|\.scr\b|\.bat\b|\.ps1\b|\.sh\b|\.cmd\b|\.com\b|\.jar\b|\.apk\b|\.dll\b|\.vbs\b|\.pkg\b|\.deb\b|\.rpm\b/i;
const ARCHIVE_EXT_RE = /\.zip\b|\.rar\b|\.7z\b|\.tar\b|\.gz\b|\.tgz\b/i;

export const descargasArchivosStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'downloads.permission_downloads',
    label: 'Permiso downloads',
    id: 'descargas_archivos',
    matches: (finding) =>
      finding.discoveryType === 'permiso_chrome_manifest_riesgoso' &&
      /downloads/i.test(finding.detail),
    evidence: (finding) =>
      `Permiso de descargas detectado en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'downloads.download_api_usage',
    label: 'Uso de API de descargas',
    id: 'descargas_archivos',
    matches: (finding) =>
      DOWNLOAD_API_RE.test(finding.detail) ||
      /download\s*\(/i.test(finding.detail),
    evidence: (finding) =>
      `Usa APIs de descarga/archivo en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'downloads.download_events',
    label: 'Escucha eventos de descargas',
    id: 'descargas_archivos',
    matches: (finding) => DOWNLOAD_EVENT_RE.test(finding.detail),
    evidence: (finding) =>
      `Reacciona a descargas en curso (onCreated/onChanged/onDeterminingFilename) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'downloads.fs_access_api',
    label: 'File System Access API',
    id: 'descargas_archivos',
    matches: (finding) => FS_ACCESS_RE.test(finding.detail),
    evidence: (finding) =>
      `Usa la File System Access API: puede leer/escribir archivos del usuario en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'downloads.blob_generation',
    label: 'Generación de archivos en cliente',
    id: 'descargas_archivos',
    matches: (finding) => BLOB_RE.test(finding.detail),
    evidence: (finding) =>
      `Construye archivos en el navegador (Blob/createObjectURL/octet-stream) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'downloads.executable_extension',
    label: 'Referencia a archivo ejecutable',
    id: 'descargas_archivos',
    matches: (finding) => EXEC_EXT_RE.test(finding.detail),
    evidence: (finding) =>
      `Aparece una ruta o URL que apunta a un archivo ejecutable o instalador en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'downloads.archive_extension',
    label: 'Referencia a archivo comprimido',
    id: 'descargas_archivos',
    matches: (finding) => ARCHIVE_EXT_RE.test(finding.detail),
    evidence: (finding) =>
      `Aparece una ruta o URL que apunta a un archivo comprimido en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateDescargasArchivos: UserRiskCategoryEvaluator = (
  context,
) => {
  const { perms } = context;
  const downloadApi = hasDetail(context, DOWNLOAD_API_RE);
  const downloadEvent = hasDetail(context, DOWNLOAD_EVENT_RE);
  const fsAccess = hasDetail(context, FS_ACCESS_RE);
  const blobGen = hasDetail(context, BLOB_RE);
  const execRef = hasDetail(context, EXEC_EXT_RE);
  const archiveRef = hasDetail(context, ARCHIVE_EXT_RE);

  // Critico: descarga + URL ejecutable (downloader malware), o intercepción + ejecutable
  const isCritical =
    (downloadApi && execRef) || (downloadEvent && (execRef || archiveRef));
  // Sospechoso: cualquier API de descargas, FS Access, o blob+exec
  const isSuspicious =
    perms.has('downloads') ||
    downloadApi ||
    downloadEvent ||
    fsAccess ||
    (blobGen && execRef);

  return makeItem(
    context,
    'descargas_archivos',
    'Descargas y archivos',
    isCritical ? 'critico' : isSuspicious ? 'sospechoso' : 'no_detectado',
    isCritical
      ? 'La extensión combina API de descargas con referencias a archivos ejecutables. Es el patrón de "downloader" de malware.'
      : fsAccess
        ? 'La extensión usa File System Access API: puede leer y escribir archivos del usuario.'
        : downloadApi || perms.has('downloads')
          ? 'Puede iniciar o gestionar descargas. Esto puede ser legítimo en gestores de descarga, pero riesgoso en extensiones sin ese propósito.'
          : 'No vimos permiso fuerte para gestionar descargas.',
    [
      perms.has('downloads') && 'Permiso downloads.',
      downloadApi &&
        'Llama a chrome.downloads.download/open/erase: puede iniciar o borrar descargas.',
      downloadEvent &&
        'Escucha chrome.downloads.onCreated/onChanged/onDeterminingFilename.',
      fsAccess &&
        'Usa showSaveFilePicker / showOpenFilePicker / FileSystemHandle.',
      blobGen &&
        'Construye archivos en el navegador (Blob/createObjectURL) para forzar descargas.',
      execRef &&
        'Aparecen rutas o URLs a archivos ejecutables (.exe, .msi, .dmg, .bat, .ps1...).',
      archiveRef &&
        'Aparecen rutas o URLs a archivos comprimidos (.zip, .7z, .tar.gz...).',
    ],
    [
      '¿Puede descargar archivos automáticamente?',
      '¿Puede generar archivos en mi equipo?',
      '¿Puede abrir o modificar descargas?',
      '¿Puede actuar como un downloader de malware?',
    ],
  );
};
