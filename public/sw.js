const CACHE_NAME = 'asistencia-cache-v1';
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

// Evento de instalación: se abre el caché y se guardan los archivos principales.
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Cache abierto');
        return cache.addAll(urlsToCache);
      })
  );
});

// Evento fetch: intercepta las peticiones de la app.
self.addEventListener('fetch', event => {
  event.respondWith(
    // Intenta buscar el recurso en el caché primero.
    caches.match(event.request)
      .then(response => {
        // Si lo encuentra en el caché, lo devuelve.
        if (response) {
          return response;
        }
        // Si no, hace la petición a la red.
        return fetch(event.request);
      })
  );
});