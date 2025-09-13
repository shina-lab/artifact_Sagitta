#!/usr/bin/env python3
from pathlib import Path
import datetime
import glob
import html
import http.server
import os
import socketserver

HTML = """
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100;0,300;0,400;0,500;0,700;0,900;1,100;1,300;1,400;1,500;1,700;1,900&display=swap" rel="stylesheet">
    <title>{title}</title>
    <style type="text/tailwindcss">
        @layer utilities {{
            body {{
                font-family: 'Roboto', sans-serif;
            }}

            .dir-name {{
                @apply px-[0.125rem] hover:bg-cyan-200 hover:cursor-pointer focus:bg-cyan-200;
            }}

            .file-list {{
                @apply grid grid-cols-8 gap-4 py-1 font-light text-gray-500 bg-white;
                &:hover {{
                    @apply text-cyan-950 bg-cyan-200;
                }}
                &:focus {{
                    @apply text-cyan-950 bg-cyan-200;
                }}
            }}

            .file-name {{
                @apply font-medium text-cyan-600 leading-6;
            }}

            .file-list:hover .file-name {{
                @apply text-cyan-950 underline decoration-solid;
            }}

            .file-icon {{
                @apply h-[24px] w-[24px] mx-2 inline-block align-text-bottom;
                background-size: contain;
            }}

            .file-icon-text {{
                background-image: url('/images/file_text.svg');
            }}

            .file-icon-image {{
                background-image: url('/images/file_image.svg');
            }}

            .file-icon-pdf {{
                background-image: url('/images/file_pdf.svg');
            }}

            .file-icon-empty {{
                background-image: url('/images/file_empty.svg');
            }}

            .file-icon-folder {{
                -webkit-mask-image: url('/images/folder.svg');
                mask-image: url('/images/folder.svg');
            }}

            .search-hit-item {{
                @apply px-4 py-2 h-fit block hover:bg-orange-950 hover:text-white focus:bg-orange-950 focus:text-white;
                & > span > b {{
                    @apply bg-orange-950;
                }}
            }}
        }}
    </style>
    <script>
        tailwind.config = {{
            darkMode: 'selector',
        }}

        window.onload = () => {{
            const searchBox = document.getElementById('search-box');
            const searchInput = document.getElementById('search');
            const searchHitItems = document.querySelectorAll('.search-hit-item');

            searchInput.addEventListener('input', (e) => {{
                const searchValue = e.target.value.toLowerCase();
                searchHitItems.forEach((hitItem) => {{
                    const name = hitItem.dataset.name;
                    const lowerCaseName = name.toLowerCase();
                    if (lowerCaseName.includes(searchValue)) {{
                        hitItem.style.display = 'block';
                        const highlightedName = name.replace(new RegExp(searchValue, 'gi'), (match) => `<b>${{match}}</b>`);
                        hitItem.querySelector('span').innerHTML = highlightedName;
                    }} else {{
                        hitItem.style.display = 'none';
                        hitItem.querySelector('span').textContent = name;
                    }}
                }});
            }});
            searchInput.blur();

            var scrollPosition = window.pageYOffset;

            window.onkeydown = openSearchBox;

            function openSearchBox(e) {{
                if (e.key === 't') {{
                    e.preventDefault(); 
                    scrollPosition = window.pageYOffset;
                    document.documentElement.classList.add('dark');
                    searchBox.setAttribute('aria-hidden', 'false');
                    searchInput.value = '';
                    searchInput.focus();
                    window.onkeydown = (e) => {{
                        if (e.key === 'Escape') {{
                            closeSearchBox();
                        }}
                    }}
                }}
            }}

            function closeSearchBox() {{
                searchBox.setAttribute('aria-hidden', 'true');
                document.documentElement.classList.remove('dark');
                searchBox.setAttribute('aria-hidden', 'true');
                window.scrollTo(0, scrollPosition);
                window.onkeydown = openSearchBox;
            }}
        }}
    </script>
</head>

<body class="bg-slate-100 dark:bg-stone-900 dark:text-stone-100 text-base dark:overflow-hidden">
    <div class="h-[80px] dark:hidden"><!-- Spacer --></div>
    <nav class="sticky dark:fixed top-0 w-[calc(100vw-160px)] dark:mt-[80px] mx-[80px] bg-slate-100 dark:bg-stone-900">
        <p class="py-2 text-base font-bold leading-none" aria-label="{path}">
            {path_selector}
        </p>
        <h1 class="mt-4 text-7xl font-bold tracking-tight hidden dark:block">{title}</h1>
    </nav>
    <h1 class="mx-[80px] mt-4 text-7xl font-bold tracking-tight dark:hidden">{title}</h1>

    <!-- Search box -->
    <div id="search-box" class="fixed top-[240px] dark:grid grid-cols-5 gap-x-4 w-[calc(100vw-160px)] mt-16 mx-[80px] font-base hidden" aria-hidden="true">
        <div class="flex col-start-2 col-span-3 p-[8px] border border-solid border-stone-500 text-stone-100">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-[16px] h-fill inline-block inline-block align-text-bottom fill-stone-500" viewBox="0 0 20 20"><path d="M18.869 19.162l-5.943-6.484c1.339-1.401 2.075-3.233 2.075-5.178 0-2.003-0.78-3.887-2.197-5.303s-3.3-2.197-5.303-2.197-3.887 0.78-5.303 2.197-2.197 3.3-2.197 5.303 0.78 3.887 2.197 5.303 3.3 2.197 5.303 2.197c1.726 0 3.362-0.579 4.688-1.645l5.943 6.483c0.099 0.108 0.233 0.162 0.369 0.162 0.121 0 0.242-0.043 0.338-0.131 0.204-0.187 0.217-0.503 0.031-0.706zM1 7.5c0-3.584 2.916-6.5 6.5-6.5s6.5 2.916 6.5 6.5-2.916 6.5-6.5 6.5-6.5-2.916-6.5-6.5z"/></svg>
            <input type="text" id="search" class="flex-1 ml-3 w-fill bg-stone-900 text-stone-950 placeholder:text-stone-500 focus:text-white focus:outline-none" placeholder="Go to result" tabindex="1" />
            <div class="h-fit px-[7px] py-[3px] inline-block align-bottom border border-solid rounded border-stone-500 text-xs text-stone-400">t</div>
        </div>
        <ul class="col-start-2 col-span-3 block m-0 -mt-px w-fill border border-solid border-stone-500 text-white">
            {search_hit_items}
        </ul>
    </div>

    <!-- File list -->
    <ul class="mt-16 mx-[80px] dark:invisible">
        {directory}     
    </ul>
</body>

</html>
"""

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def list_directory(self, path):
        path = Path(path)

        path_selector = ''
        for i, p in enumerate(path.parts[1:-1]):
            href = '../' * (len(path.parts) - i)
            path_selector += '<span>/</span>'
            path_selector += f'<a class="dir-name" href="{href}">{p}</a>'
        path_selector += '<span>/</span>'

        search_hit_items = ''
        for i, name in enumerate(sorted(os.listdir(os.getcwd()))):
            if name.startswith('.') or name.startswith('__') or name.startswith('._') or name.startswith('~'):
                continue
            if not os.path.exists(f"{name}/result/"):
                continue
            if os.path.isdir(name):
                search_hit_items += f"""
                <li>
                    <a href="/{name}/result/" class="search-hit-item" data-name="{name}" tabindex="{i + 2}">
                        <div class="file-icon file-icon-folder bg-orange-600"></div>
                        <span aria-hidden="true">{name}</span>
                    </a>
                </li>
            """

        directory = ''
        for file_name in sorted(os.listdir(path)):
            if file_name.startswith('.') or file_name.startswith('__') or file_name.startswith('._') or file_name.startswith('~'):
                continue
            if file_name.endswith('.log') or file_name.endswith('.dot') or file_name.endswith('.gml') or file_name.endswith('.out'):
                continue
            
            item_path = path / file_name
            file_size = item_path.stat().st_size
            if file_size < 1024:
                file_size = f'{file_size} <small>bytes</small>'
            elif file_size < 1024 * 1024:
                file_size = f'{file_size / 1024:.1f} <small>KB</small>'
            elif file_size < 1024 * 1024 * 1024:
                file_size = f'{file_size / 1024 / 1024:.1f} <small>MB</small>'
            else:
                file_size = f'{file_size / 1024 / 1024 / 1024:.1f} <small>GB</small>'
            
            file_class_name = 'text'
            if item_path.is_dir():
                file_class_name = 'folder bg-cyan-500'
            if file_name.endswith('.svg') or file_name.endswith('.png') or file_name.endswith('.jpg') or file_name.endswith('.jpeg'):
                file_class_name = 'image'
            if file_name.endswith('pdf'):
                file_class_name = 'pdf'
            
            file_modified_date = datetime.datetime.fromtimestamp(
                os.path.getmtime(path / file_name)
            ).strftime('%Y/%m/%d %H:%M')

            directory += f"""
        <li>
            <a href="{file_name}" class="file-list">
                <div class="col-start-1 col-span-5">
                    <div class="file-icon file-icon-{file_class_name}"><!-- File icon--></div>
                    <span class="file-name">{file_name}</span> 
                </div>
                <div class="col-start-6 text-sm leading-6">{file_size}</div>
                <div class="col-start-7 col-span-2 text-sm leading-6">{file_modified_date}</div>
            </a>
        </li>
            """

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            HTML.format(
                title=html.escape(path.name),
                path=html.escape(str(path)),
                path_selector=path_selector,
                search_hit_items=search_hit_items,
                directory=directory,
            ).encode('utf-8')
        )
        
PORT = 8000
with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
    print("[*] Serving HTTP server at port", PORT)
    httpd.serve_forever()