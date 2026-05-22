<?xml version="1.0" encoding="utf-8"?>
<!--
Nmap Bootstrap XSL — Dark Modern Theme
Original by Andreas Hontzia (@honze_net) & LRVT (@l4rm4nd)
Aesthetic overhaul applied
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>

  <!-- ══════════════════════════════════════════════════════════════
       KEYS (unchanged logic)
       ══════════════════════════════════════════════════════════════ -->
  <xsl:key name="svcByProduct"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="@product"/>
  <xsl:key name="svcByProdVer"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version)"/>
  <xsl:key name="svcByProdVerHost"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version,'|', ancestor::host/address/@addr)"/>
  <xsl:key name="svcByProdVerHostPort"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version,'|',
                       ancestor::host/address/@addr,'|',
                       ../@protocol,'|',../@portid)"/>
  <xsl:key name="sshSvcs"
           match="nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']"
           use="1"/>
  <xsl:key name="httpTitleByProdVer"
           match="nmaprun/host/ports/port[state/@state='open' and @protocol='tcp']
                  /script[@id='http-title']/elem[@key='title'][contains(normalize-space(.), '/')]"
           use="concat(
                  substring-before(normalize-space(.), '/'),
                  '|',
                  substring-after(normalize-space(.), '/')
               )"/>
  <xsl:key name="httpTitleByProdVerHostPort"
           match="nmaprun/host/ports/port[state/@state='open' and @protocol='tcp']
                  /script[@id='http-title']/elem[@key='title'][contains(normalize-space(.), '/')]"
           use="concat(
                  substring-before(normalize-space(.), '/'),
                  '|',
                  substring-after(normalize-space(.), '/'),
                  '|',
                  ancestor::host/address/@addr,
                  '|',
                  ancestor::port[1]/@protocol,
                  '|',
                  ancestor::port[1]/@portid
               )"/>

  <!-- ══════════════════════════════════════════════════════════════
       MAIN TEMPLATE
       ══════════════════════════════════════════════════════════════ -->
  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <meta name="referrer" content="no-referrer"/>

        <!-- ── External Dependencies ── -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous"/>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous"/>
        <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.0.1/css/buttons.dataTables.min.css" integrity="sha384-0OeHd2TJxoSDnW9bOIukOL7+BcfI6b17OHv54+JWrUbWq7ABgBO0rjW3OinB5vbG" crossorigin="anonymous"/>
        <link rel="stylesheet" href="https://cdn.datatables.net/1.10.19/css/dataTables.bootstrap.min.css" type="text/css" integrity="sha384-VEpVDzPR2x8NbTDZ8NFW4AWbtT2g/ollEzX/daZdW/YvUBlbgVtsxMftnJ84k0Cn" crossorigin="anonymous"/>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet"/>

        <script src="https://code.jquery.com/jquery-3.3.1.js" integrity="sha384-fJU6sGmyn07b+uD1nMk7/iSb4yvaowcueiQhfVgQuD98rfva8mcr1eSvjchfpMrH" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js" integrity="sha384-rgWRqC0OFPisxlUvl332tiM/qmaNxnlY46eksSZD84t+s2vZlqGeHrncwIRX7CGp" crossorigin="anonymous"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.1.3/jszip.min.js" integrity="sha384-v9EFJbsxLXyYar8TvBV8zu5USBoaOC+ZB57GzCmQiWfgDIjS+wANZMP5gjwMLwGv" crossorigin="anonymous"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.1.53/pdfmake.min.js" integrity="sha384-HUHsYVOhSyHyZRTWv8zkbKVk7Xmg12CCNfKEUJ7cSuW/22Lz3BITd3Om6QeiXICb" crossorigin="anonymous"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.1.53/vfs_fonts.js" integrity="sha384-UAA3vlTPq9dwxB61awBFhR7Y5uBFOKQWuZueu4C6uI48gjIoqI/OTmYWEYWZXbGR" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/buttons/2.0.1/js/dataTables.buttons.min.js" integrity="sha384-MGimb05YiSGNcXiLlj03UNahXBECHmFTe5iVBqh6sf2G7ccabI3/EOqzBnNw97/T" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/buttons/2.0.1/js/buttons.html5.min.js" integrity="sha384-pp2ArcKo71umWphZ7QCCjQbnICkbOkLF88ZeoeZDPbqdAVvxZlcrla3lyT7pY/ue" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/buttons/2.0.1/js/buttons.colVis.min.js" integrity="sha384-enGTgEZOvC7C8P91Jt/27n1V3xD5SIzGi1e+DzYJvAts546YTsj3CNmnL0G/zlVn" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/buttons/2.0.1/js/buttons.bootstrap.min.js" integrity="sha384-Ndtz/aMKkdc9b0uTCirKXA6kJ8QfBTv73Ph9sv0wOiqK7NENdLN+qTpPX5skuhiM" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/1.10.19/js/dataTables.bootstrap.min.js" integrity="sha384-7PXRkl4YJnEpP8uU4ev9652TTZSxrqC8uOpcV1ftVEC7LVyLZqqDUAaq+Y+lGgr9" crossorigin="anonymous"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/plug-ins/2.1.0/sorting/ip-address.js" integrity="sha384-pbrITLqgA4lSZJgcYMK/c5hfUpOg+2vjjMQPdRv4hPEoBFYVWEuF1H3faZskzO9a" crossorigin="anonymous"></script>

        <style>
 
:root {

  /* ═════════ BACKGROUNDS ═════════ */
  --bg-page:        #0B0A1A;
  --bg-card:        #1B193C;
  --bg-card-alt:    #221F4A;
  --bg-hover:       #2A2860;
  --bg-input:       #221F4A;
  --bg-code:        #1F1D46;

  --bg-dark:        #0B0A1A;
  --bg-dark-card:   #1B193C;
  --bg-dark-inner:  #221F4A;
  --bg-navbar:      #0F0E23;

  /* ═════════ TEXT ═════════ */
  --text-primary:   #E6E8FF;
  --text-secondary: #B6B8E6;
  --text-muted:     #7F82B3;

  --text-on-dark:         #F2F3FF;
  --text-on-dark-muted:   #9DA1D6;

  /* ═════════ BORDERS ═════════ */
  --border-color:   #333468;
  --border-subtle:  #2A2860;
  --border-dark:    #3A3C80;

  /* ═════════ ACCENTS ═════════ */

  --accent-purple:        #6C5EF3;
  --accent-purple-hover:  #7C6BFF;
  --accent-purple-light:  rgba(108,94,243,0.15);
  --accent-purple-glow:   rgba(108,94,243,0.35);

  --accent-pink:          #BB48F5;
  --accent-pink-light:    rgba(187,72,245,0.18);

  --accent-blue:          #47A0EE;
  --accent-blue-light:    rgba(71,160,238,0.18);

  --accent-cyan:          #3ED6D0;
  --accent-cyan-light:    rgba(62,214,208,0.18);

  /* ═════════ STATUS COLORS ═════════ */

  --color-open:           #3ED6D0;
  --color-closed:         #FF5C7A;
  --color-filtered:       #F6C34A;

  /* ═════════ LINKS ═════════ */

  --accent-link:          #6C5EF3;
  --accent-link-hover:    #BB48F5;

  /* ═════════ GRADIENTS (like the image cards) ═════════ */

  --accent-gradient:
    linear-gradient(135deg,#6C5EF3 0%, #BB48F5 45%, #47A0EE 100%);

  --accent-gradient-soft:
    linear-gradient(135deg,#4C459A 0%, #6C5EF3 60%, #47A0EE 100%);

  /* ═════════ SHADOWS (glow style) ═════════ */

  --shadow-sm:
    0 4px 12px rgba(0,0,0,0.35);

  --shadow-md:
    0 10px 30px rgba(0,0,0,0.45);

  --shadow-lg:
    0 20px 60px rgba(0,0,0,0.55);

  --shadow-glow:
    0 0 20px rgba(108,94,243,0.35);

  --shadow-card:
    0 6px 30px rgba(0,0,0,0.45);

  /* ═════════ RADIUS ═════════ */

  --radius-sm: 8px;
  --radius-md: 14px;
  --radius-lg: 20px;

  /* ═════════ TYPOGRAPHY ═════════ */

  --font-sans:
    'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;

  --font-mono:
    'JetBrains Mono','Fira Code','Cascadia Code', monospace;

  --transition:
    all 0.25s cubic-bezier(.4,0,.2,1);
}
/* ═══════════════════════════════════════════════
   GLOBAL RESET / BASE
   ═══════════════════════════════════════════════ */
*, *::before, *::after { box-sizing: border-box; }

html {
  scroll-behavior: smooth;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  background:
    radial-gradient(circle at 20% 20%, #1B193C 0%, transparent 40%),
    radial-gradient(circle at 80% 10%, #4C459A 0%, transparent 35%),
    linear-gradient(160deg,#0B0A1A 0%, #141233 100%);
  font-family: var(--font-sans);
  background-color: var(--bg-page);
  color: var(--text-primary);
  line-height: 1.6;
  margin: 0;
  padding: 0;
}

::selection {
  background: var(--accent-purple-glow);
  color: var(--text-primary);
}

a {
  color: var(--accent-link);
  text-decoration: none;
  transition: var(--transition);
}
a:hover, a:focus {
  color: var(--accent-link-hover);
  text-decoration: none;
}

h1, h2, h3, h4, h5, h6 {
  font-weight: 600;
  color: var(--text-primary);
  letter-spacing: -0.02em;
}

/* ═══════════════════════════════════════════════
   SCROLL TARGET OFFSET
   ═══════════════════════════════════════════════ */
.target:before {
  content: "";
  display: block;
  height: 80px;
  margin: -80px 0 0;
}

/* ═══════════════════════════════════════════════
   CONTAINER
   ═══════════════════════════════════════════════ */
@media only screen and (min-width:1900px) {
  .container { width: 1800px; }
}

/* ═══════════════════════════════════════════════
   NAVBAR — Dark bar matching sidebar from ref
   ═══════════════════════════════════════════════ */
.navbar-default {
  background: var(--bg-navbar);
  border: none;
  border-bottom: 1px solid var(--border-dark);
  box-shadow: 0 2px 20px rgba(26, 26, 46, 0.15);
  min-height: 56px;
  margin-bottom: 0;
}
.navbar-default .navbar-brand {
  color: var(--text-on-dark);
  font-weight: 700;
  font-size: 1.1em;
  padding: 16px 20px;
  transition: var(--transition);
}
.navbar-default .navbar-brand:hover {
  color: var(--accent-purple);
  transform: scale(1.05);
}
.navbar-default .navbar-nav > li > a {
  color: var(--text-on-dark-muted);
  font-size: 0.875rem;
  font-weight: 500;
  padding: 18px 14px;
  transition: var(--transition);
  position: relative;
}
.navbar-default .navbar-nav > li > a:hover,
.navbar-default .navbar-nav > li > a:focus {
  color: #FFFFFF;
  background: transparent;
}
.navbar-default .navbar-nav > li > a::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 50%;
  transform: translateX(-50%) scaleX(0);
  width: 70%;
  height: 2px;
  background: var(--accent-gradient);
  border-radius: 2px;
  transition: transform 0.3s ease;
}
.navbar-default .navbar-nav > li > a:hover::after {
  transform: translateX(-50%) scaleX(1);
}
.navbar-default .navbar-toggle {
  border-color: var(--border-dark);
}
.navbar-default .navbar-toggle .icon-bar {
  background-color: var(--text-on-dark-muted);
}
.navbar-default .navbar-toggle:hover .icon-bar,
.navbar-default .navbar-toggle:focus .icon-bar {
  background-color: var(--accent-purple);
}
.navbar-default .navbar-collapse {
  border-color: var(--border-dark);
}
/* Override Bootstrap mobile collapse bg */
@media (max-width: 767px) {
  .navbar-default .navbar-collapse {
    background: var(--bg-navbar);
  }
}

/* ═══════════════════════════════════════════════
   JUMBOTRON / HERO
   ═══════════════════════════════════════════════ */
.jumbotron {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-card);
  margin-top: 80px;
  padding: 40px 40px 32px;
  position: relative;
  overflow: hidden;
}
.jumbotron::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: var(--accent-gradient);
}
.jumbotron h2 {
  font-size: 2rem;
  font-weight: 700;
  margin-top: 8px;
  margin-bottom: 12px;
  color: var(--text-primary);
}
.jumbotron h2 small {
  display: block;
  color: var(--text-secondary);
  font-size: 0.55em;
  font-weight: 400;
  margin-top: 6px;
  line-height: 1.7;
}
.jumbotron pre {
   background: #2B3855;
  color: var(--accent-teal);
  border: 1px solid var(--border-dark);
  border-radius: var(--radius-md);
  padding: 16px 20px;
  font-family: var(--font-mono);
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-wrap: break-word;
  margin: 20px 0;
}
.jumbotron pre a {
  color: var(--accent-teal);
}
.jumbotron pre a:hover {
  color: var(--accent-purple);
}
.jumbotron .lead {
  color: var(--text-secondary);
  font-size: 1.05rem;
  font-weight: 400;
  margin-bottom: 20px;
}

/* ═══════════════════════════════════════════════
   PROGRESS BAR
   ═══════════════════════════════════════════════ */
.progress {
  background: var(--bg-code);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  height: 28px;
  box-shadow: inset 0 1px 3px rgba(26, 26, 46, 0.06);
  overflow: hidden;
  margin-bottom: 24px;
}
.progress-bar {
  font-size: 0.8rem;
  font-weight: 600;
  line-height: 28px;
  color: #FFFFFF;
  transition: width 1s ease;
}
.progress-bar-success {
  background: linear-gradient(90deg, #2DB89A, #3ECFB2);
  box-shadow: 0 0 12px rgba(62, 207, 178, 0.2);
}
.progress-bar-danger {
  background: linear-gradient(90deg, #D1532F, #E8613C);
  box-shadow: 0 0 12px rgba(232, 97, 60, 0.2);
}

/* ═══════════════════════════════════════════════
   KEYWORD FORM
   ═══════════════════════════════════════════════ */
#form-wrapper textarea {
  background: var(--bg-input);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 10px 14px;
  font-family: var(--font-mono);
  font-size: 0.85rem;
  resize: vertical;
  transition: var(--transition);
  width: 100%;
}
#form-wrapper textarea:focus {
  border-color: var(--accent-purple);
  outline: none;
  box-shadow: 0 0 0 3px var(--accent-purple-glow);
}
#form-wrapper textarea::placeholder {
  color: var(--text-muted);
}
#form-wrapper button {
  background: var(--bg-card);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 8px 18px;
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition: var(--transition);
  margin-right: 6px;
}
#form-wrapper button:hover {
  background: var(--accent-purple);
  border-color: var(--accent-purple);
  color: #FFFFFF;
  box-shadow: 0 4px 14px rgba(123, 97, 255, 0.25);
}
#credits {
  color: var(--text-muted);
  font-size: 0.82rem;
}
#credits a {
  color: var(--text-secondary);
}
#credits a:hover {
  color: var(--accent-purple);
}

/* ═══════════════════════════════════════════════
   SECTION HEADINGS — Purple accent
   ═══════════════════════════════════════════════ */
h2.target, h2#scannedhosts, h2#openservices, h2#webservices,
h2#productversions, h2#ssh-auth, h2#onlinehosts {
  font-size: 1.6rem;
  font-weight: 700;
  color: var(--text-primary);
  margin: 48px 0 20px;
  padding-bottom: 12px;
  border-bottom: 2px solid var(--border-color);
  position: relative;
}
h2.target::after, h2#onlinehosts::after {
  content: '';
  position: absolute;
  bottom: -2px;
  left: 0;
  width: 60px;
  height: 2px;
  background: var(--accent-gradient);
  border-radius: 2px;
}
h2 small {
  color: var(--text-muted);
  font-size: 0.6em;
}

/* ═══════════════════════════════════════════════
   LABELS / BADGES
   ═══════════════════════════════════════════════ */
.label {
  font-size: 0.75rem;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 20px;
  letter-spacing: 0.03em;
  text-transform: uppercase;
}
.label-success {
  background: var(--accent-teal-light);
  color: #2A9D83;
  border: 1px solid rgba(62, 207, 178, 0.25);
}
.label-danger {
  background: var(--accent-orange-light);
  color: #C44D2D;
  border: 1px solid rgba(232, 97, 60, 0.25);
}

/* ═══════════════════════════════════════════════
   TABLES (Global)
   ═══════════════════════════════════════════════ */
.table-responsive {
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  overflow: hidden;
  box-shadow: var(--shadow-card);
  margin-bottom: 32px;
  background: var(--bg-card);
}
table.table,
table.dataTable {
  background: var(--bg-card);
  color: var(--text-primary);
  border-collapse: separate;
  border-spacing: 0;
  margin-bottom: 0;
  width: 100% !important;
}
table.table thead th,
table.dataTable thead th {
  background: var(--bg-card-alt);
  color: var(--text-secondary);
  border-bottom: 2px solid var(--border-color) !important;
  border-top: none;
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 14px 16px;
  white-space: nowrap;
}
table.table tbody td,
table.dataTable tbody td {
  border-top: 1px solid var(--border-subtle);
  padding: 12px 16px;
  font-size: 0.875rem;
  vertical-align: middle;
  transition: var(--transition);
}
table.table tbody tr:hover td,
table.dataTable tbody tr:hover td {
  background: var(--bg-hover) !important;
}
table.table-striped > tbody > tr:nth-of-type(odd) {
  background-color: var(--bg-card-alt);
}
table.table-striped > tbody > tr:nth-of-type(even) {
  background-color: var(--bg-card);
}

/* Port state colors in Online Hosts */
table.table-bordered tbody tr.success > td {
  background: var(--accent-teal-light);
  border-color: var(--border-subtle);
}
table.table-bordered tbody tr.warning > td {
  background: rgba(245, 166, 35, 0.08);
  border-color: var(--border-subtle);
}
table.table-bordered tbody tr.active > td {
  background: var(--bg-card-alt);
  border-color: var(--border-subtle);
}
table.table-bordered tbody tr.info > td {
  background: var(--accent-blue-light);
  border-color: var(--border-subtle);
}
table.table-bordered {
  border-color: var(--border-color);
}
table.table-bordered > thead > tr > th,
table.table-bordered > tbody > tr > td {
  border-color: var(--border-subtle);
}

/* ═══════════════════════════════════════════════
   DATATABLES OVERRIDES
   ═══════════════════════════════════════════════ */
.dataTables_wrapper {
  padding: 16px;
  background: var(--bg-card);
}
.dataTables_wrapper .dataTables_length label,
.dataTables_wrapper .dataTables_filter label,
.dataTables_wrapper .dataTables_info,
.dataTables_wrapper .dataTables_paginate {
  color: var(--text-secondary);
  font-size: 0.85rem;
}
.dataTables_wrapper .dataTables_length select,
.dataTables_wrapper .dataTables_filter input {
  background: var(--bg-input);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 6px 12px;
  transition: var(--transition);
}
.dataTables_wrapper .dataTables_filter input:focus {
  border-color: var(--accent-purple);
  outline: none;
  box-shadow: 0 0 0 3px var(--accent-purple-glow);
}
.dataTables_wrapper .dataTables_paginate .paginate_button {
  color: var(--text-secondary) !important;
  background: var(--bg-card) !important;
  border: 1px solid var(--border-color) !important;
  border-radius: var(--radius-sm) !important;
  margin: 0 2px;
  padding: 6px 12px !important;
  transition: var(--transition);
}
.dataTables_wrapper .dataTables_paginate .paginate_button:hover {
  background: var(--accent-purple) !important;
  color: #FFFFFF !important;
  border-color: var(--accent-purple) !important;
}
.dataTables_wrapper .dataTables_paginate .paginate_button.current {
  background: var(--accent-purple) !important;
  color: #FFFFFF !important;
  border-color: var(--accent-purple) !important;
  font-weight: 600;
  box-shadow: 0 2px 8px rgba(123, 97, 255, 0.2);
}
.dataTables_wrapper .dataTables_paginate .paginate_button.disabled {
  opacity: 0.35;
  cursor: not-allowed;
}
table.dataTable thead .sorting::after,
table.dataTable thead .sorting_asc::after,
table.dataTable thead .sorting_desc::after {
  opacity: 0.4;
}
table.dataTable thead .sorting_asc::after,
table.dataTable thead .sorting_desc::after {
  opacity: 1;
  color: var(--accent-purple);
}

/* DataTables Buttons */
.dt-buttons .dt-button,
.dt-buttons .btn {
  background: var(--bg-card) !important;
  color: var(--text-secondary) !important;
  border: 1px solid var(--border-color) !important;
  border-radius: var(--radius-sm) !important;
  font-size: 0.8rem !important;
  font-weight: 500;
  padding: 6px 14px !important;
  margin: 0 4px 8px 0;
  transition: var(--transition);
}
.dt-buttons .dt-button:hover,
.dt-buttons .btn:hover {
  background: var(--accent-purple) !important;
  color: #FFFFFF !important;
  border-color: var(--accent-purple) !important;
  box-shadow: 0 2px 8px rgba(123, 97, 255, 0.2);
}

/* ═══════════════════════════════════════════════
   PANELS (Online Hosts)
   ═══════════════════════════════════════════════ */
.panel {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  margin-bottom: 16px;
  transition: var(--transition);
}
.panel:hover {
  border-color: rgba(123, 97, 255, 0.2);
  box-shadow: var(--shadow-md);
}
.panel-default > .panel-heading {
  background: var(--bg-card-alt);
  border-bottom: 1px solid var(--border-color);
  border-radius: var(--radius-md) var(--radius-md) 0 0;
  padding: 16px 20px;
  cursor: pointer;
  transition: var(--transition);
}
.panel-default > .panel-heading:hover {
  background: var(--bg-hover);
}
.panel-heading > h3.panel-title {
  font-size: 1rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0;
}
.panel-heading > h3:before {
  font-family: 'Glyphicons Halflings';
  content: "\e114";
  padding-right: 12px;
  color: var(--accent-purple);
  font-size: 0.8em;
  transition: var(--transition);
}
.panel-heading.collapsed > h3:before {
  content: "\e080";
  color: var(--text-muted);
}
.panel-body {
  background: var(--bg-card);
  padding: 20px 24px;
  border-radius: 0 0 var(--radius-md) var(--radius-md);
}
.panel-body h4 {
  font-size: 1rem;
  font-weight: 600;
  color: var(--accent-purple);
  margin: 24px 0 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border-subtle);
}
.panel-body h4:first-child {
  margin-top: 0;
}
.panel-body h5 {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--text-primary);
  margin: 16px 0 8px;
}
.panel-body ul {
  padding-left: 20px;
}
.panel-body ul li {
  color: var(--text-secondary);
  padding: 2px 0;
}
.panel-body pre {
   background: #3A4A6B;        /* lighter than #2B3855 */
  color: #E0E6FF;             /* lighter text for contrast */
  border: 1px solid #556680;  /* softer border */
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  font-family: var(--font-mono);
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-wrap: break-word;
  line-height: 1.6;
  max-height: 400px;
  overflow-y: auto;
}

/* ═══════════════════════════════════════════════
   FOOTER
   ═══════════════════════════════════════════════ */
.footer {
  margin-top: 60px;
  padding: 40px 0;
  width: 100%;
  background: var(--bg-dark);
  border-top: 1px solid var(--border-dark);
}
.footer .text-muted {
  color: var(--text-on-dark-muted);
  font-size: 0.85rem;
  line-height: 1.8;
}
.footer a {
  color: var(--text-on-dark-muted);
}
.footer a:hover {
  color: var(--accent-purple);
}

/* ═══════════════════════════════════════════════
   UTILITY
   ═══════════════════════════════════════════════ */
.clickable { cursor: pointer; }

/* Scrollbar — light theme */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}
::-webkit-scrollbar-track {
  background: var(--bg-page);
}
::-webkit-scrollbar-thumb {
  background: var(--border-color);
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
  background: var(--text-muted);
}

.glyphicon-new-window { font-size: 0.85em; }
.glyphicon-heart { font-size: 0.85em; }

/* Entrance animations */
@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: translateY(0); }
}
.jumbotron {
  animation: fadeInUp 0.6s ease-out;
}
.table-responsive {
  animation: fadeInUp 0.6s ease-out both;
}
.panel {
  animation: fadeInUp 0.4s ease-out both;
}

        </style>
        <title>Nmap Scan Results</title>
      </head>
      <body>
        <!-- ══════════════════════════════════════════════
             HIGHLIGHT SCRIPT
             ══════════════════════════════════════════════ -->
        <script>
          function highlight(){
              $("#table-services").dataTable().fnDestroy()
              let keywords = document.getElementById('keyword-input').value.split(',');
              let content = document.getElementById('table-services').innerHTML;
              document.getElementById('table-services').innerHTML = transformContent(content, keywords)
              $('#table-services').DataTable( {
              "lengthMenu": [ [5, 10, 25, 50, 100, -1], [5, 10, 25, 50, 100, "All"] ],
              "order": [[ 0, 'desc' ]],
              "columnDefs": [
                { "targets": [0], "orderable": true },
              ],
              dom:'lBfrtip',
              stateSave: true,
              buttons: [
                  {
                      extend: 'copyHtml5',
                      exportOptions: { orthogonal: 'export' }
                  },
                  {
                      extend: 'csvHtml5',
                      exportOptions: { orthogonal: 'export' }
                  },
                  {
                      extend: 'excelHtml5',
                      exportOptions: { orthogonal: 'export' },
                      autoFilter: true,
                      title: '',
                  },
                  {
                      extend: 'pdfHtml5',
                      exportOptions: { orthogonal: 'export' },
                      orientation: 'landscape',
                      pageSize: 'LEGAL',
                      download: 'open',
                      exportOptions: {
                      columns: [ 0,1,2,3,4,5,6,7,8 ]
                }
                  }
              ],
            });
          }

          function transformContent(content, keywords){
            let temp = content
            keywords.forEach(keyword => {
              temp = temp.replace(new RegExp(keyword, 'ig'), wrapKeywordWithHTML(keyword, keyword))
            })
            return temp
          }

          function wrapKeywordWithHTML(keyword, url){
            return `<![CDATA[<span style="color: #EF4444; font-weight: 600; background: rgba(239, 68, 68, 0.1); padding: 1px 4px; border-radius: 3px;">${keyword}</span>]]>`
          }
        </script>

        <!-- ══════════════════════════════════════════════
             NAVBAR
             ══════════════════════════════════════════════ -->
        <nav class="navbar navbar-default navbar-fixed-top">
          <div class="container-fluid">
            <div class="navbar-header">
              <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1" aria-expanded="false">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
              </button>
              <a class="navbar-brand" href="#"><span class="glyphicon glyphicon-home"></span></a>
            </div>
            <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
              <ul class="nav navbar-nav">
                <li><a href="#scannedhosts">Scanned Hosts</a></li>
                <li><a href="#openservices">Open Services</a></li>
                <li><a href="#webservices">Web Services</a></li>
                <li><a href="#productversions">Product Versions</a></li>
                <xsl:if test="count(/nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']) &gt; 0">
                  <li><a href="#ssh-auth">SSH Auth</a></li>
                </xsl:if>
                <li><a href="#onlinehosts">Online Hosts</a></li>
                <li><a href="#" style="pointer-events: none; cursor: default; opacity: 0.2;">|</a></li>
                <li><a href="https://www.pentestfactory.de/schwachstellendatenbank/" target="_blank" title="Vulnerability Database by Pentest Factory"><span class="glyphicon glyphicon-new-window" style="color: #F59E0B;"></span> CVEs</a></li>
                <li><a href="https://www.ssllabs.com/ssltest/" target="_blank" title="SSL Server Test by Qualys"><span class="glyphicon glyphicon-new-window" style="color: #EF4444;"></span> SSL/TLS</a></li>
                <li><a href="https://securityheaders.com/" target="_blank" title="HTTP Header Test by Scott Helme"><span class="glyphicon glyphicon-new-window" style="color: #38BDF8;"></span> Headers</a></li>
              </ul>
            </div>
          </div>
        </nav>

        <!-- ══════════════════════════════════════════════
             MAIN CONTENT
             ══════════════════════════════════════════════ -->
        <div class="container" style="width: 94%">

          <!-- ── Hero / Jumbotron ── -->
          <div class="jumbotron">
            <h2>Nmap Port Scanning Results</h2>
            <h2><small>Nmap Version <xsl:value-of select="/nmaprun/@version"/>
            <br/><xsl:value-of select="/nmaprun/@startstr"/> – <xsl:value-of select="/nmaprun/runstats/finished/@timestr"/></small></h2>
            <pre><a target="_blank"><xsl:attribute name="href">https://explainshell.com/explain?cmd=<xsl:value-of select="/nmaprun/@args"/></xsl:attribute><xsl:value-of select="/nmaprun/@args"/></a></pre>
            <p class="lead">
              <xsl:value-of select="/nmaprun/runstats/hosts/@total"/> hosts scanned.
              <xsl:value-of select="/nmaprun/runstats/hosts/@up"/> hosts up.
              <xsl:value-of select="/nmaprun/runstats/hosts/@down"/> hosts down.
            </p>
            <div class="progress">
              <div class="progress-bar progress-bar-success" style="width: 0%">
                <xsl:attribute name="style">width:<xsl:value-of select="/nmaprun/runstats/hosts/@up div /nmaprun/runstats/hosts/@total * 100"/>%;</xsl:attribute>
                <xsl:value-of select="/nmaprun/runstats/hosts/@up"/>
                <span class="sr-only"></span>
              </div>
              <div class="progress-bar progress-bar-danger" style="width: 0%">
                <xsl:attribute name="style">width:<xsl:value-of select="/nmaprun/runstats/hosts/@down div /nmaprun/runstats/hosts/@total * 100"/>%;</xsl:attribute>
                <xsl:value-of select="/nmaprun/runstats/hosts/@down"/>
                <span class="sr-only"></span>
              </div>
            </div>
            <div id="form-wrapper">
              <div>
                <textarea title="Insert comma separated keywords to be highlighted" rows="1" name="keywords" placeholder="sha1,password,..." id="keyword-input">sha1,login,password,md5</textarea>
              </div>
              <div style="margin-top: 8px">
                <button title="Keyword highlighting in 'Open Services'" id="highlight-button" onclick="highlight()">⚡ Highlight Keywords</button>
                <button title="Reset keyword highlighting" id="reset-highlight-button" onclick="document.location.reload(true);">↺ Reset</button>
              </div>
              <div style="margin-top: 25px" id="credits">
                <div><span class="glyphicon glyphicon-heart" style="color: #EF4444; padding-right: 5px"></span><a href="https://github.com/Haxxnet/nmap-bootstrap-xsl">Nmap Bootstrap XSL</a> by <a href="https://github.com/l4rm4nd">LRVT</a></div>
              </div>
            </div>
          </div>
          <div class="container">
  <div class="row">
    <div class="col-md-12">
      <div class="graph-card">
       

        <div class="graph-wrapper">
        <div style="text-align:left; margin-bottom:10px;">
  <span style="color:#E74C3C;">■ Critical</span>
  <span style="color:#E67E22; margin-left:10px;">■ High</span>
  <span style="color:#F1C40F; margin-left:10px;">■ Medium</span>
</div>
          
        </div>
      </div>
    </div>
  </div>
</div>

          <!-- ═══════════════════════════════════════════
               SCANNED HOSTS TABLE
               ═══════════════════════════════════════════ -->
          <h2 id="scannedhosts" class="target">Scanned Hosts<xsl:if test="/nmaprun/runstats/hosts/@down > 1024"><small> (offline hosts are hidden)</small></xsl:if></h2>
          <div class="table-responsive">
            <table id="table-overview" class="table table-striped dataTable" role="grid">
              <thead>
                <tr>
                  <th>State</th>
                  <th>Address</th>
                  <th>Hostname</th>
                  <th>TCP (open)</th>
                  <th>UDP (open)</th>
                </tr>
              </thead>
              <tbody>
                <xsl:choose>
                  <xsl:when test="/nmaprun/runstats/hosts/@down > 1024">
                    <xsl:for-each select="/nmaprun/host[status/@state='up']">
                      <tr>
                        <td><span class="label label-danger"><xsl:if test="status/@state='up'"><xsl:attribute name="class">label label-success</xsl:attribute></xsl:if><xsl:value-of select="status/@state"/></span></td>
                        <td><a><xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute><xsl:value-of select="address/@addr"/></a></td>
                        <td><xsl:value-of select="hostnames/hostname/@name"/></td>
                        <td><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                        <td><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                      </tr>
                    </xsl:for-each>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:for-each select="/nmaprun/host">
                      <tr>
                        <td><span class="label label-danger"><xsl:if test="status/@state='up'"><xsl:attribute name="class">label label-success</xsl:attribute></xsl:if><xsl:value-of select="status/@state"/></span></td>
                        <td><a><xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute><xsl:value-of select="address/@addr"/></a></td>
                        <td><xsl:value-of select="hostnames/hostname/@name"/></td>
                        <td><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                        <td><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                      </tr>
                    </xsl:for-each>
                  </xsl:otherwise>
                </xsl:choose>
              </tbody>
            </table>
          </div>

          <!-- ═══════════════════════════════════════════
               OPEN SERVICES TABLE
               ═══════════════════════════════════════════ -->
          <h2 id="openservices" class="target">Open Services</h2>
          <div class="table-responsive">
            <table id="table-services" class="table table-striped dataTable" role="grid">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Address</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>Service</th>
                  <th>Product</th>
                  <th>Version</th>
                  <th>Extra</th>
                  <th>SSL Certificate</th>
                  <th title="Title of HTTP services">Title</th>
                  <th>CPE</th>
                </tr>
              </thead>
              <tbody>
                <xsl:for-each select="/nmaprun/host">
                  <xsl:for-each select="ports/port[state/@state='open']">
                    <tr>
                      <td>
                        <xsl:if test="count(../../hostnames/hostname) = 0">N/A</xsl:if>
                        <xsl:if test="count(../../hostnames/hostname) > 0"><xsl:value-of select="../../hostnames/hostname/@name"/></xsl:if>
                      </td>
                      <td><a><xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/></xsl:attribute><xsl:value-of select="../../address/@addr"/></a></td>
                      <td><a><xsl:attribute name="href">#port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute><xsl:value-of select="@portid"/></a></td>
                      <td><xsl:value-of select="@protocol"/></td>
                      <td><xsl:if test="count(service/@tunnel) > 0"><xsl:value-of select="service/@tunnel"/>/</xsl:if><xsl:value-of select="service/@name"/></td>
                      <td><xsl:value-of select="service/@product"/></td>
                      <td><xsl:value-of select="service/@version"/></td>
                      <td><xsl:value-of select="service/@extrainfo"/></td>
                      <td>
                        <xsl:if test="count(script/table[@key='subject']/elem[@key='commonName']) > 0">CN: <i><xsl:value-of select="script/table[@key='subject']/elem[@key='commonName']"/></i></xsl:if>
                        <xsl:if test="count(script/table[@key='validity']/elem[@key='notAfter']) > 0"><br/>Expiry: <i><xsl:value-of select="script/table[@key='validity']/elem[@key='notAfter']"/></i></xsl:if>
                        <xsl:if test="count(script/elem[@key='sig_algo']) > 0"><br/>SigAlgo: <i><xsl:value-of select="script/elem[@key='sig_algo']"/></i></xsl:if>
                      </td>
                      <td>
                        <xsl:choose>
                          <xsl:when test="count(script[@id='http-title']/elem[@key='title']) > 0"><i><xsl:value-of select="script[@id='http-title']/elem[@key='title']"/></i></xsl:when>
                          <xsl:otherwise><xsl:if test="count(script[@id='http-title']/@output) > 0"><i><xsl:value-of select="script[@id='http-title']/@output"/></i></xsl:if></xsl:otherwise>
                        </xsl:choose>
                      </td>
                      <td>
                        <xsl:variable name="c22" select="service/cpe"/>
                        <xsl:variable name="afterA" select="substring-after($c22, 'cpe:/a:')"/>
                        <xsl:variable name="vendor" select="substring-before($afterA, ':')"/>
                        <xsl:variable name="afterVendor" select="substring-after($afterA, ':')"/>
                        <xsl:variable name="product" select="substring-before($afterVendor, ':')"/>
                        <xsl:variable name="verRaw" select="substring-after($afterVendor, ':')"/>
                        <xsl:variable name="verNorm" select="substring-before(concat($verRaw,'-'), '-')"/>
                        <xsl:variable name="verFinal" select="normalize-space($verNorm)"/>
                        <xsl:choose>
                          <xsl:when test="string($c22)">
                            <xsl:choose>
                              <xsl:when test="string-length($verFinal) &gt; 0">
                                <a title="Click to find known CVEs" target="_blank">
                                  <xsl:attribute name="href">https://cve.pentestfactory.de/?cpe=<xsl:value-of select="$c22"/></xsl:attribute>
                                  <xsl:value-of select="$c22"/>
                                </a>
                              </xsl:when>
                              <xsl:otherwise><xsl:value-of select="$c22"/></xsl:otherwise>
                            </xsl:choose>
                          </xsl:when>
                          <xsl:otherwise>unknown</xsl:otherwise>
                        </xsl:choose>
                      </td>
                    </tr>
                  </xsl:for-each>
                </xsl:for-each>
              </tbody>
            </table>
          </div>

          <!-- ═══════════════════════════════════════════
               WEB SERVICES TABLE
               ═══════════════════════════════════════════ -->
          <h2 id="webservices" class="target">Web Services</h2>
          <div class="table-responsive">
            <table id="web-services" class="table table-striped dataTable" role="grid">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Address</th>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Product</th>
                  <th>Version</th>
                  <th>Title</th>
                  <th>SSL Certificate</th>
                  <th>URL</th>
                </tr>
              </thead>
              <tbody>
                <xsl:for-each select="/nmaprun/host">
                  <xsl:for-each select="ports/port[starts-with(service/@name, 'http') and state/@state='open' and @protocol='tcp']">
                    <tr>
                      <td>
                        <xsl:if test="count(../../hostnames/hostname) = 0">N/A</xsl:if>
                        <xsl:if test="count(../../hostnames/hostname) > 0"><xsl:value-of select="../../hostnames/hostname/@name"/></xsl:if>
                      </td>
                      <td><a><xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/></xsl:attribute><xsl:value-of select="../../address/@addr"/></a></td>
                      <td><a><xsl:attribute name="href">#port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute><xsl:value-of select="@portid"/></a></td>
                      <td><xsl:if test="count(service/@tunnel) > 0"><xsl:value-of select="service/@tunnel"/>/</xsl:if><xsl:value-of select="service/@name"/></td>
                      <td><xsl:value-of select="service/@product"/></td>
                      <td><xsl:value-of select="service/@version"/></td>
                      <td>
                        <xsl:choose>
                          <xsl:when test="count(script[@id='http-title']/elem[@key='title']) > 0"><i><xsl:value-of select="script[@id='http-title']/elem[@key='title']"/></i></xsl:when>
                          <xsl:otherwise><xsl:if test="count(script[@id='http-title']/@output) > 0"><i><xsl:value-of select="script[@id='http-title']/@output"/></i></xsl:if></xsl:otherwise>
                        </xsl:choose>
                      </td>
                      <td>
                        <xsl:if test="count(script/table[@key='subject']/elem[@key='commonName']) > 0">CN: <i><xsl:value-of select="script/table[@key='subject']/elem[@key='commonName']"/></i></xsl:if>
                        <xsl:if test="count(script/table[@key='validity']/elem[@key='notAfter']) > 0"><br/>Expiry: <i><xsl:value-of select="script/table[@key='validity']/elem[@key='notAfter']"/></i></xsl:if>
                        <xsl:if test="count(script/elem[@key='sig_algo']) > 0"><br/>SigAlgo: <i><xsl:value-of select="script/elem[@key='sig_algo']"/></i></xsl:if>
                      </td>
                      <xsl:choose>
                        <xsl:when test="count(service/@tunnel) > 0 or service/@name = 'https' or service/@name = 'https-alt'">
                          <td>
                            <xsl:if test="count(../../hostnames/hostname) > 0"><a target="_blank" href="https://{../../hostnames/hostname/@name}:{@portid}">https://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/></a></xsl:if>
                            <xsl:if test="count(../../hostnames/hostname) = 0"><a target="_blank" href="https://{../../address/@addr}:{@portid}">https://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/></a></xsl:if>
                          </td>
                        </xsl:when>
                        <xsl:otherwise>
                          <td>
                            <xsl:if test="count(../../hostnames/hostname) > 0"><a target="_blank" href="http://{../../hostnames/hostname/@name}:{@portid}">http://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/></a></xsl:if>
                            <xsl:if test="count(../../hostnames/hostname) = 0"><a target="_blank" href="http://{../../address/@addr}:{@portid}">http://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/></a></xsl:if>
                          </td>
                        </xsl:otherwise>
                      </xsl:choose>
                    </tr>
                  </xsl:for-each>
                </xsl:for-each>
              </tbody>
            </table>
          </div>

          <!-- ═══════════════════════════════════════════
               PRODUCT VERSIONS TABLE
               ═══════════════════════════════════════════ -->
          <h2 id="productversions" class="target">Product Versions</h2>
          <div class="table-responsive">
            <table id="table-product-versions" class="table table-striped dataTable" role="grid">
              <thead>
                <tr>
                  <th>Product</th>
                  <th>Version</th>
                  <th>Count</th>
                  <th>Host List</th>
                  <th>CPE</th>
                </tr>
              </thead>
              <tbody>
                <xsl:for-each
                  select="/nmaprun/host/ports/port[state/@state='open']/service[@product and @version]
                          [generate-id() = generate-id(key('svcByProdVer', concat(@product,'|',@version))[1])]">
                  <xsl:sort select="@product"/>
                  <xsl:sort select="@version"/>

                  <xsl:variable name="pv" select="concat(@product,'|',@version)"/>
                  <xsl:variable name="services" select="key('svcByProdVer', $pv)"/>
                  <xsl:variable name="uniqHosts"
                    select="$services[generate-id() =
                            generate-id(key('svcByProdVerHost',
                                            concat(@product,'|',@version,'|', ancestor::host/address/@addr))[1])]"/>

                  <xsl:variable name="cpe22" select="$services/cpe[starts-with(., 'cpe:/a:')][1]"/>
                  <xsl:variable name="afterA" select="substring-after($cpe22, 'cpe:/a:')"/>
                  <xsl:variable name="vendor" select="substring-before($afterA, ':')"/>
                  <xsl:variable name="afterVendor" select="substring-after($afterA, ':')"/>
                  <xsl:variable name="product" select="substring-before($afterVendor, ':')"/>
                  <xsl:variable name="verRaw" select="substring-after($afterVendor, ':')"/>
                  <xsl:variable name="verNorm" select="substring-before(concat($verRaw,'-'), '-')"/>
                  <xsl:variable name="verFinal" select="normalize-space($verNorm)"/>
                  <xsl:variable name="verOrStar">
                    <xsl:choose>
                      <xsl:when test="string-length($verFinal) &gt; 0"><xsl:value-of select="$verFinal"/></xsl:when>
                      <xsl:otherwise>*</xsl:otherwise>
                    </xsl:choose>
                  </xsl:variable>

                  <xsl:variable name="svcHostPortDistinct"
                    select="$services[generate-id() =
                            generate-id(key('svcByProdVerHostPort',
                              concat(@product,'|',@version,'|',
                                     ancestor::host/address/@addr,'|',
                                     ../@protocol,'|', ../@portid))[1])]"/>

                  <tr>
                    <td><xsl:value-of select="@product"/></td>
                    <td><xsl:value-of select="@version"/></td>
                    <td><xsl:value-of select="count($uniqHosts)"/></td>
                    <td>
                      <xsl:for-each select="key('svcByProdVer', $pv)
                                            [generate-id() =
                                             generate-id(key('svcByProdVerHostPort',
                                               concat(@product,'|',@version,'|',
                                                      ancestor::host/address/@addr,'|',
                                                      ../@protocol,'|',../@portid))[1])]">
                        <xsl:sort select="ancestor::host/hostnames/hostname[1]/@name"/>
                        <xsl:sort select="ancestor::host/address/@addr"/>
                        <xsl:sort select="../@protocol"/>
                        <xsl:sort select="../@portid" data-type="number"/>

                        <xsl:variable name="h"  select="ancestor::host"/>
                        <xsl:variable name="ip" select="$h/address/@addr"/>
                        <xsl:variable name="hn" select="$h/hostnames/hostname[1]/@name"/>
                        <xsl:variable name="proto" select="translate(../@protocol, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
                        <xsl:variable name="port"  select="../@portid"/>

                        <a>
                          <xsl:attribute name="href">#port-<xsl:value-of select="translate($ip, '.', '-')"/>-<xsl:value-of select="$port"/></xsl:attribute>
                          <xsl:choose>
                            <xsl:when test="string-length($hn) &gt; 0">
                              <xsl:value-of select="$hn"/> (<xsl:value-of select="$ip"/>)
                            </xsl:when>
                            <xsl:otherwise><xsl:value-of select="$ip"/></xsl:otherwise>
                          </xsl:choose>
                          <xsl:text> [</xsl:text><xsl:value-of select="$proto"/><xsl:text>/</xsl:text><xsl:value-of select="$port"/><xsl:text>]</xsl:text>
                        </a>
                        <xsl:if test="position() != last()">, </xsl:if>
                      </xsl:for-each>
                    </td>
                    <td>
                      <xsl:choose>
                        <xsl:when test="string($cpe22)">
                          <xsl:choose>
                            <xsl:when test="string-length($verFinal) &gt; 0">
                              <a title="Click to find known CVEs" target="_blank">
                                <xsl:attribute name="href">https://cve.pentestfactory.de/?cpe=<xsl:value-of select="$cpe22"/></xsl:attribute>
                                <xsl:value-of select="$cpe22"/>
                              </a>
                            </xsl:when>
                            <xsl:otherwise><xsl:value-of select="$cpe22"/></xsl:otherwise>
                          </xsl:choose>
                        </xsl:when>
                        <xsl:otherwise>unknown</xsl:otherwise>
                      </xsl:choose>
                    </td>
                  </tr>
                </xsl:for-each>
              </tbody>
            </table>
          </div>

          <!-- ═══════════════════════════════════════════
               SSH AUTHENTICATION TABLE (conditional)
               ═══════════════════════════════════════════ -->
          <xsl:if test="count(/nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']) &gt; 0">
            <h2 id="ssh-auth" class="target">SSH Authentication</h2>
            <div class="table-responsive">
              <table id="table-ssh-auth" class="table table-striped dataTable" role="grid">
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>IP</th>
                    <th>Port</th>
                    <th>Product</th>
                    <th>Version</th>
                    <th>Auth Methods</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="key('sshSvcs', 1)">
                    <xsl:sort select="ancestor::host/hostnames/hostname[1]/@name"/>
                    <xsl:sort select="ancestor::host/address/@addr"/>
                    <xsl:sort select="../@portid" data-type="number"/>

                    <xsl:variable name="host" select="ancestor::host"/>
                    <xsl:variable name="ip"   select="$host/address/@addr"/>
                    <xsl:variable name="hn"   select="$host/hostnames/hostname[1]/@name"/>
                    <xsl:variable name="port" select="../@portid"/>
                    <xsl:variable name="proto" select="translate(../@protocol,'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
                    <xsl:variable name="methods" select="../script[@id='ssh-auth-methods']/table[@key='Supported authentication methods']/elem"/>
                    <xsl:variable name="hasPassword" select="$methods[translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='password']"/>
                    <xsl:variable name="hasPublickey" select="$methods[translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='publickey']"/>
                    <xsl:variable name="hasKI" select="$methods[translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='keyboard-interactive']"/>
                    <xsl:variable name="class">
                      <xsl:choose>
                        <xsl:when test="count($methods) &gt; 0 and count($methods)=count($methods[translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='publickey'])">Public key only</xsl:when>
                        <xsl:when test="$hasPassword or $hasKI">Password allowed</xsl:when>
                        <xsl:otherwise>Unknown</xsl:otherwise>
                      </xsl:choose>
                    </xsl:variable>

                    <tr>
                      <td>
                        <xsl:choose>
                          <xsl:when test="string-length($hn) &gt; 0"><xsl:value-of select="$hn"/></xsl:when>
                          <xsl:otherwise>-</xsl:otherwise>
                        </xsl:choose>
                      </td>
                      <td>
                        <a><xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate($ip,'.','-')"/></xsl:attribute><xsl:value-of select="$ip"/></a>
                      </td>
                      <td>
                        <a><xsl:attribute name="href">#port-<xsl:value-of select="translate($ip,'.','-')"/>-<xsl:value-of select="$port"/></xsl:attribute><xsl:value-of select="$proto"/>/<xsl:value-of select="$port"/></a>
                      </td>
                      <td><xsl:value-of select="@product"/></td>
                      <td><xsl:value-of select="@version"/></td>
                      <td>
                        <xsl:choose>
                          <xsl:when test="count($methods) &gt; 0">
                            <xsl:for-each select="$methods">
                              <xsl:value-of select="."/>
                              <xsl:if test="position()!=last()">, </xsl:if>
                            </xsl:for-each>
                          </xsl:when>
                          <xsl:otherwise>-</xsl:otherwise>
                        </xsl:choose>
                      </td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </xsl:if>

          <!-- ═══════════════════════════════════════════
               ONLINE HOSTS (Collapsible Panels)
               ═══════════════════════════════════════════ -->
          <h2 id="onlinehosts" class="target">Online Hosts</h2>
          <xsl:for-each select="/nmaprun/host[status/@state='up']">
            <div class="panel panel-default">
              <div class="panel-heading clickable" data-toggle="collapse">
                <xsl:attribute name="id">onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                <xsl:attribute name="data-target">#<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                <h3 class="panel-title"><xsl:value-of select="address/@addr"/><xsl:if test="count(hostnames/hostname) > 0"> – <xsl:value-of select="hostnames/hostname/@name"/></xsl:if></h3>
              </div>
              <div class="panel-body collapse in">
                <xsl:attribute name="id"><xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                <xsl:if test="count(hostnames/hostname) > 0">
                  <h4>Hostnames</h4>
                  <ul>
                    <xsl:for-each select="hostnames/hostname">
                      <li><xsl:value-of select="@name"/> (<xsl:value-of select="@type"/>)</li>
                    </xsl:for-each>
                  </ul>
                </xsl:if>
                <h4>Ports</h4>
                <div class="table-responsive" style="box-shadow: none; border-radius: var(--radius-sm);">
                  <table class="table table-bordered">
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State / Reason</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                        <th>Extra Info</th>
                      </tr>
                    </thead>
                    <tbody>
                      <xsl:for-each select="ports/port">
                        <xsl:choose>
                          <xsl:when test="state/@state = 'open'">
                            <tr class="success">
                              <td title="Port"><xsl:attribute name="id">port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute><xsl:value-of select="@portid"/></td>
                              <td title="Protocol"><xsl:value-of select="@protocol"/></td>
                              <td title="State / Reason"><xsl:value-of select="state/@state"/><br/><xsl:value-of select="state/@reason"/></td>
                              <td title="Service"><xsl:if test="count(service/@tunnel) > 0"><xsl:value-of select="service/@tunnel"/>/</xsl:if><xsl:value-of select="service/@name"/></td>
                              <td title="Product"><xsl:value-of select="service/@product"/></td>
                              <td title="Version"><xsl:value-of select="service/@version"/></td>
                              <td title="Extra Info"><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                            <tr>
                              <td colspan="7">
                                <a><xsl:attribute name="href">https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;cves=on&amp;cpe_version=<xsl:value-of select="service/cpe"/></xsl:attribute><xsl:value-of select="service/cpe"/></a>
                                <xsl:for-each select="script">
                                  <h5><xsl:value-of select="@id"/></h5>
                                  <pre><xsl:value-of select="@output"/></pre>
                                </xsl:for-each>
                              </td>
                            </tr>
                          </xsl:when>
                          <xsl:when test="state/@state = 'filtered'">
                            <tr class="warning">
                              <td><xsl:value-of select="@portid"/></td>
                              <td><xsl:value-of select="@protocol"/></td>
                              <td><xsl:value-of select="state/@state"/><br/><xsl:value-of select="state/@reason"/></td>
                              <td><xsl:value-of select="service/@name"/></td>
                              <td><xsl:value-of select="service/@product"/></td>
                              <td><xsl:value-of select="service/@version"/></td>
                              <td><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                          </xsl:when>
                          <xsl:when test="state/@state = 'closed'">
                            <tr class="active">
                              <td><xsl:value-of select="@portid"/></td>
                              <td><xsl:value-of select="@protocol"/></td>
                              <td><xsl:value-of select="state/@state"/><br/><xsl:value-of select="state/@reason"/></td>
                              <td><xsl:value-of select="service/@name"/></td>
                              <td><xsl:value-of select="service/@product"/></td>
                              <td><xsl:value-of select="service/@version"/></td>
                              <td><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                          </xsl:when>
                          <xsl:otherwise>
                            <tr class="info">
                              <td><xsl:value-of select="@portid"/></td>
                              <td><xsl:value-of select="@protocol"/></td>
                              <td><xsl:value-of select="state/@state"/><br/><xsl:value-of select="state/@reason"/></td>
                              <td><xsl:value-of select="service/@name"/></td>
                              <td><xsl:value-of select="service/@product"/></td>
                              <td><xsl:value-of select="service/@version"/></td>
                              <td><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                          </xsl:otherwise>
                        </xsl:choose>
                      </xsl:for-each>
                    </tbody>
                  </table>
                </div>
                <xsl:if test="count(hostscript/script) > 0">
                  <h4>Host Script</h4>
                </xsl:if>
                <xsl:for-each select="hostscript/script">
                  <h5><xsl:value-of select="@id"/></h5>
                  <pre><xsl:value-of select="@output"/></pre>
                </xsl:for-each>
                <xsl:if test="count(os/osmatch) > 0">
                  <h4>OS Detection</h4>
                  <xsl:for-each select="os/osmatch">
                    <h5>OS details: <xsl:value-of select="@name"/> (<xsl:value-of select="@accuracy"/>%)</h5>
                    <xsl:for-each select="osclass">
                      Device type: <xsl:value-of select="@type"/><br/>
                      Running: <xsl:value-of select="@vendor"/><xsl:text> </xsl:text><xsl:value-of select="@osfamily"/><xsl:text> </xsl:text><xsl:value-of select="@osgen"/> (<xsl:value-of select="@accuracy"/>%)<br/>
                      OS CPE: <a><xsl:attribute name="href">https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;cves=on&amp;cpe_version=<xsl:value-of select="cpe"/></xsl:attribute><xsl:value-of select="cpe"/></a>
                      <br/>
                    </xsl:for-each>
                    <br/>
                  </xsl:for-each>
                </xsl:if>
              </div>
            </div>
          </xsl:for-each>
        </div>

        <!-- ══════════════════════════════════════════════
             FOOTER
             ══════════════════════════════════════════════ -->
        <footer class="footer">
          <div class="container">
            <p class="text-muted">
              This report was generated by or with the help of <a href="https://pentestfactory.com">Pentest Factory GmbH</a>.<br/>
              If you have questions or problems do not hesitate <a href="mailto:team@pentestfactory.de">contacting us</a>.<br/><br/>
              <span class="glyphicon glyphicon-heart" style="color: #EF4444;"></span> Bootstrap Template by <a href="https://github.com/honze-net/nmap-bootstrap-xsl" target="_blank">Andreas Hontzia</a><br/>
              <span class="glyphicon glyphicon-heart" style="color: #EF4444;"></span> Tweaks and Extensions by <a href="https://github.com/l4rm4nd">LRVT</a>
            </p>
          </div>
        </footer>

        <!-- ══════════════════════════════════════════════
             DATATABLE INITIALIZATIONS
             ══════════════════════════════════════════════ -->
        <script>
          $(document).ready(function() {
            $('#table-services').DataTable();
            $("a[href^='#onlinehosts-']").click(function(event){
                event.preventDefault();
                $('html,body').animate({scrollTop:($(this.hash).offset().top-60)}, 500);
            });
          });
          $('#table-services').DataTable( {
            "lengthMenu": [ [5, 10, 25, 50, 100, -1], [5, 10, 25, 50, 100, "All"] ],
            "order": [[ 0, 'desc' ]],
            "columnDefs": [
              { "targets": [0], "orderable": true },
              { "targets": [1], "type": "ip-address" },
            ],
            dom:'lBfrtip',
            stateSave: true,
            buttons: [
                {
                    extend: 'copyHtml5',
                    exportOptions: { orthogonal: 'export' }
                },
                {
                    extend: 'csvHtml5',
                    exportOptions: { orthogonal: 'export' }
                },
                {
                    extend: 'excelHtml5',
                    exportOptions: { orthogonal: 'export' },
                    autoFilter: true,
                    title: '',
                },
                {
                    extend: 'pdfHtml5',
                    orientation: 'landscape',
                    pageSize: 'LEGAL',
                    download: 'open',
                    exportOptions: {
                      columns: [ 0,1,2,3,4,5,6,7,8 ]
                    }
                }
            ],
          });
        </script>
        <script>
          $(document).ready(function() {
            $('#web-services').DataTable();
          });
          $('#web-services').DataTable( {
            "lengthMenu": [ [5, 10, 25, 50, 100, -1], [5, 10, 25, 50, 100, "All"] ],
            "order": [[ 0, 'desc' ]],
            "columnDefs": [
              { "targets": [0], "orderable": true },
              { "targets": [1], "type": "ip-address" },
            ],
            dom:'lBfrtip',
            stateSave: true,
            buttons: [
                {
                    extend: 'copyHtml5',
                    exportOptions: { orthogonal: 'export' }
                },
                {
                    extend: 'csvHtml5',
                    exportOptions: { orthogonal: 'export' }
                },
                {
                    extend: 'excelHtml5',
                    exportOptions: { orthogonal: 'export' },
                    autoFilter: true,
                    title: '',
                },
                {
                    extend: 'pdfHtml5',
                    orientation: 'landscape',
                    pageSize: 'LEGAL',
                    download: 'open',
                    exportOptions: {
                      columns: [ 0,1,2,3,4,5,6,7,8 ]
                    }
                }
            ],
          });
        </script>
        <script>
          $(document).ready(function() {
            $('#table-overview').DataTable();
          });
          $('#table-overview').DataTable( {
            "lengthMenu": [ [5, 10, 25, 50, 100, -1], [5, 10, 25, 50, 100, "All"] ],
            "columnDefs": [
              { "targets": [1], "type": "ip-address" },
            ],
          });
        </script>
        <script>
          $(document).ready(function() {
            $('#table-product-versions').DataTable();
          });
          $('#table-product-versions').DataTable({
            "lengthMenu": [ [5, 10, 25, 50, 100, -1], [5, 10, 25, 50, 100, "All"] ],
            "order": [[ 0, 'asc' ], [1, 'asc' ]],
            dom: 'lBfrtip',
            stateSave: true,
            buttons: [
              { extend: 'copyHtml5', exportOptions: { orthogonal: 'export' } },
              { extend: 'csvHtml5',  exportOptions: { orthogonal: 'export' } },
              { extend: 'excelHtml5', exportOptions: { orthogonal: 'export' }, autoFilter: true, title: '' },
              { extend: 'pdfHtml5', orientation: 'landscape', pageSize: 'LEGAL', download: 'open',
                exportOptions: { columns: [0,1,2,3,4,5] } }
            ],
          });
        </script>
        <script>
          $(function () {
            if ($('#table-ssh-auth').length) {
              $('#table-ssh-auth').DataTable({
                lengthMenu: [ [5, 10, 25, 50, 100, -1], [5, 10, 25, 50, 100, "All"] ],
                order: [[0, 'asc'], [2, 'asc']],
                columnDefs: [
                  { targets: 1, type: 'ip-address' }
                ],
                dom: 'lBfrtip',
                stateSave: true,
                buttons: [
                  { extend: 'copyHtml5',  exportOptions: { columns: [0,1,2,3,4,5] } },
                  { extend: 'csvHtml5',   exportOptions: { columns: [0,1,2,3,4,5] } },
                  { extend: 'excelHtml5', exportOptions: { columns: [0,1,2,3,4,5] }, autoFilter: true, title: '' },
                  { extend: 'pdfHtml5',   orientation: 'landscape', pageSize: 'LEGAL', download: 'open',
                    exportOptions: { columns: [0,1,2,3,4,5] } }
                ]
              });
            }
          });
        </script>
        <script>
          <![CDATA[
            $(function () {
              $('.panel-heading.clickable').on('click', function (e) {
                var sel = '';
                if (window.getSelection) {
                  sel = window.getSelection().toString();
                } else if (document.selection && document.selection.type !== 'Control') {
                  sel = document.selection.createRange().text;
                }
                if (sel && sel.length > 0) {
                  e.preventDefault();
                  e.stopPropagation();
                }
              });
            });
          ]]>
        </script>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>