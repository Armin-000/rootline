# Rootline — Domain Surface Inventory

Rootline is a responsive public-domain inventory workspace for certificate records, DNS resolution and HTTPS reachability.

## Vercel-ready structure

```text
rootline/
├── api/
│   ├── health.mjs
│   └── scan.mjs
├── lib/
│   └── scan-service.mjs
├── public/
│   ├── assets/
│   ├── app.js
│   ├── index.html
│   ├── manifest.webmanifest
│   ├── styles.css
│   └── sw.js
├── tests/
├── dev-server.mjs
├── package.json
└── vercel.json
```

Only `public/` is served as the website. Vercel automatically deploys files inside `/api` as Node.js Functions, while the shared scan logic stays outside the public directory.

## Run locally

Requirements: Node.js 22.

```bash
npm run verify
npm run dev
```

Open:

```text
http://localhost:4173
```

Health check:

```text
http://localhost:4173/api/health
```

To use it on a phone connected to the same Wi-Fi, run `ipconfig`, find the computer's IPv4 address and open:

```text
http://YOUR_LOCAL_IP:4173
```

Allow Node.js through the Windows private-network firewall when prompted.

## Deploy from GitHub to Vercel

1. Push the complete project to the `main` branch.
2. In Vercel, select **Add New → Project**.
3. Import the `rootline` GitHub repository.
4. The repository configuration already defines the deployment settings in `vercel.json`:

```text
Framework Preset: Other
Build Command: skipped
Output Directory: public
Root Directory: ./
```

5. Deploy. No environment variables are required.

After deployment, verify:

```text
https://YOUR-PROJECT.vercel.app/api/health
```

Then open the application and run a scan. The frontend calls the same-origin endpoint `/api/scan`.

## Vercel configuration

`vercel.json` provides:

- an explicit `public/` output directory
- no frontend build step
- Frankfurt (`fra1`) execution for the API function
- a 60-second maximum scan duration
- cancellation support
- service-worker cache revalidation
- security headers and a restrictive Content Security Policy

## Product behavior

- Cert Spotter is the primary discovery source.
- crt.sh is used as a fallback.
- The root domain is checked even when certificate sources are unavailable.
- DNS resolution includes IPv4, IPv6 and CNAME records.
- HTTPS checks are skipped for private, local and reserved IP addresses.
- Results and scan history remain in the current browser.
- A scan is capped at 48 public hosts so it remains inside serverless execution limits.
- Use the public deployment only for domains you own or are authorized to assess.

## Validation

```bash
npm run verify
```

## Theme behavior

Rootline starts in light mode for first-time visitors, regardless of the operating-system theme. An explicit light or dark selection is stored locally and restored on later visits. The small `public/theme-init.js` bootstrap applies the stored selection before the stylesheet renders, preventing a visible theme flash while remaining compatible with the project's Content Security Policy.

