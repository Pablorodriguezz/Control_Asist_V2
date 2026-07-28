const CACHE_NAME = 'asistencia-cache-v2';
const urlsToCache = [
  '/',
  '/index.html',
  '/panel.html',
  '/admin.html',
  '/vacaciones.html',
  '/fichaje-rapido.html',
  '/style.css',
  '/images/dad1.png',
  '/images/logo2.png',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css'
];

// Instalación: cachea los archivos principales y activa el SW nuevo de inmediato.
self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
});

// Activación: borra las cachés antiguas para que no sirvan páginas viejas.
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(nombres =>
      Promise.all(nombres.filter(n => n !== CACHE_NAME).map(n => caches.delete(n)))
    ).then(() => self.clients.claim())
  );
});

// Fetch: network-first. Trae siempre lo último; si no hay red, tira de la caché.
self.addEventListener('fetch', event => {
  event.respondWith(
    fetch(event.request)
      .then(respuesta => {
        // Solo cacheamos GET (POST/PUT/DELETE no se pueden guardar en caché).
        if (event.request.method === 'GET') {
          const copia = respuesta.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, copia)).catch(() => {});
        }
        return respuesta;
      })
      .catch(() => caches.match(event.request))
  );
});
