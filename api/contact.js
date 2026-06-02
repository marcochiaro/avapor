// Endpoint para el formulario de sugerencias.
// Valida Cloudflare Turnstile antes de reenviar a Formspree.
//
// Variables de entorno requeridas en Vercel:
//   TURNSTILE_SECRET_KEY  -> Secret key del sitio en Cloudflare Turnstile
//   FORMSPREE_ENDPOINT    -> URL completa del form de Formspree (ej. https://formspree.io/f/xxxx)

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const body = req.body || {};

    // Honeypot: si esta lleno es un bot
    if (body._gotcha) {
        return res.status(200).json({ ok: true });
    }

    // Tiempo minimo desde que se cargo la pagina (anti-bot rapido)
    const loadedAt = Number(body._t || 0);
    if (loadedAt && Date.now() - loadedAt < 2000) {
        return res.status(400).json({ error: 'Demasiado rapido' });
    }

    const token = body['cf-turnstile-response'];
    if (!token) {
        return res.status(400).json({ error: 'Captcha faltante' });
    }

    const secret = process.env.TURNSTILE_SECRET_KEY;
    const formspreeEndpoint = process.env.FORMSPREE_ENDPOINT;
    if (!secret || !formspreeEndpoint) {
        return res.status(500).json({ error: 'Servidor mal configurado' });
    }

    // Validar token con Cloudflare
    const remoteip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    const verifyParams = new URLSearchParams({ secret, response: token });
    if (remoteip) verifyParams.append('remoteip', remoteip);

    try {
        const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: verifyParams,
        });
        const verifyData = await verifyRes.json();
        if (!verifyData.success) {
            return res.status(403).json({ error: 'Captcha invalido' });
        }
    } catch {
        return res.status(502).json({ error: 'No se pudo validar el captcha' });
    }

    // Validacion basica de campos
    const nombre = String(body.nombre || '').trim();
    const email = String(body.email || '').trim();
    const tipo = String(body.tipo || '').trim();
    const mensaje = String(body.mensaje || '').trim();

    if (!nombre || !email || !mensaje) {
        return res.status(400).json({ error: 'Faltan campos requeridos' });
    }
    if (nombre.length > 120 || email.length > 200 || mensaje.length > 4000) {
        return res.status(400).json({ error: 'Campos demasiado largos' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Email invalido' });
    }

    // Reenviar a Formspree
    try {
        const fsRes = await fetch(formspreeEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({
                nombre,
                email,
                tipo,
                mensaje,
                _subject: 'Sugerencia desde la web de Avapor',
            }),
        });
        if (!fsRes.ok) {
            return res.status(502).json({ error: 'No se pudo enviar el mensaje' });
        }
    } catch {
        return res.status(502).json({ error: 'No se pudo enviar el mensaje' });
    }

    return res.status(200).json({ ok: true });
}
