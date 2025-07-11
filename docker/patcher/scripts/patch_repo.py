import argparse
import pathlib
import shutil
import subprocess
import json
import re

def run(cmd, cwd=None, **kw):
    subprocess.run(cmd, check=True, cwd=cwd, **kw)

def update_proxy_config_for_dev(file_path):
    """Update proxy.config.js for development environment to target localhost:30080"""
    with open(file_path, 'r') as f:
        content = f.read()

    # Replace the target with localhost:30080 for development mode
    new_content = content.replace("http://localhost:8008", "http://localhost:30008")

    with open(file_path, 'w') as f:
        f.write(new_content)


# def replace_links(file_path, links):
#     """Replace the hard-coded links in the environment/base.ts"""
#     with open(file_path, 'r') as f:
#         content = f.read()

#     # Replace links in BASE_ENV object
#     for key, value in links.items():
#         # Match the key names in the BASE_ENV object and replace them with the new values
#         content = re.sub(f'"{key}":\s*"[^\"]*"', f'"{key}": "{value}"', content)

#     # Also replace the branding URLs (logo, logoSmall, faviconUrl)
#     if 'faviconUrl' in links:
#         content = re.sub(r'"faviconUrl":\s*"[^\"]*"', f'"faviconUrl": "{links["faviconUrl"]}"', content)
#     if 'logo' in links:
#         content = re.sub(r'"logo":\s*"[^\"]*"', f'"logo": "{links["logo"]}"', content)
#     if 'logoSmall' in links:
#         content = re.sub(r'"logoSmall":\s*"[^\"]*"', f'"logoSmall": "{links["logoSmall"]}"', content)

#     with open(file_path, 'w') as f:
#         f.write(content)

def replace_links(links, repo_dir):
    """Replace the hard-coded links in files specified in the links dictionary."""
    for key, data in links.items():
        url = data.get("url")
        original = data.get("original")
        files = data.get("files", [])

        # Iterate over all files associated with the current link
        for file_path in files:
            # Ensure that file_path is resolved relative to the cloned repo
            file_path = repo_dir / pathlib.Path(file_path)  # Convert to absolute path relative to repo_dir
            
            try:
                with open(file_path, 'r') as f:
                    content = f.read()

                # Replace the URL in the file
                content = re.sub(re.escape(original), url, content)

                # Write back the modified content to the file
                with open(file_path, 'w') as f:
                    f.write(content)
                print(f"Updated {file_path} with new URL: {url}")
            except FileNotFoundError:
                print(f"Error: {file_path} not found. Skipping...")

def replace_title_in_index_html(file_path, brand_name):
    """Replace the <title> in index.html with the provided brand name."""
    with open(file_path, 'r') as f:
        content = f.read()

    # Replace the <title> content
    new_content = content.replace("<title>ClearML</title>", f"<title>{brand_name}</title>")

    with open(file_path, 'w') as f:
        f.write(new_content)

def main():
    # Define input arguments
    p = argparse.ArgumentParser()
    p.add_argument("--logo-dir", required=True, help="Directory containing logo files")
    p.add_argument("--brand-name", required=True, help="Brand name to replace ClearML")
    p.add_argument("--links-json", required=True, help="JSON file with links (e.g., GitHub, YouTube, Docs)")
    p.add_argument("--style-file", required=True, help="Single style file (e.g., colors.scss)")
    p.add_argument("--dev-mode", action='store_true', help="Flag to enable development mode (default: False)")
    args = p.parse_args()

    # Load links from the JSON file
    with open(args.links_json, 'r') as f:
        links = json.load(f)

    # If in dev mode, clone the repo
    if args.dev_mode:
        # The repo will be cloned when in dev mode
        print("Cloning the ClearML web repo...")
        repo_dir = pathlib.Path("/tmp/clearml-web")
        run(["git", "clone", "--branch", "master", "https://github.com/allegroai/clearml-web.git", str(repo_dir)])
    else:
        # If not in dev mode, assume the repo is already available in the container
        repo_dir = pathlib.Path("/opt/open-webapp")

    # Replace logos (logos go to src/assets)
    logos_dir = pathlib.Path(args.logo_dir)
    logos = ["logo.svg", "logo-white.svg", "small-logo.svg", "small-logo-white.svg"]
    
    # Handle logos that go into the src folder (favicon.ico)
    favicon_files = ["favicon.ico"]
    for logo in favicon_files:
        logo_src = logos_dir / logo
        logo_dest = repo_dir / "src" / logo  # Placing the favicon in the src folder
        shutil.copy(logo_src, logo_dest)

    # Handle other logos that go into the assets folder
    for logo in logos:
        if logo not in favicon_files:  # Skip favicon files since they are already handled
            logo_src = logos_dir / logo
            logo_dest = repo_dir / "src" / "assets" / logo
            shutil.copy(logo_src, logo_dest)

    # Replace brand name in the repo (search and replace in multiple files)
    for file_path in repo_dir.glob("**/*.ts"):
        with open(file_path, 'r') as f:
            content = f.read()
        content = content.replace("ClearML", args.brand_name)
        with open(file_path, 'w') as f:
            f.write(content)

    # Replace links in environment/base.ts
    # base_env_file = repo_dir / "src" / "environments" / "base.ts"
    # replace_links(base_env_file, links)
    
    # Replace links in files (dynamically checking for key with '_files')
    replace_links(links, repo_dir)


    # Replace title in index.html
    index_html_path = repo_dir / "src" / "index.html"
    replace_title_in_index_html(index_html_path, args.brand_name)

    # Hardcoded paste directory relative to the cloned repo
    paste_dir = repo_dir / "src" / "app" / "webapp-common" / "styles" / "customizations" / "colors.scss"

    # Copy the custom style file to the hardcoded target directory
    shutil.copy(args.style_file, paste_dir)

    # If we're in dev mode, update the proxy config file
    if args.dev_mode:
        proxy_config_path = repo_dir / "proxy.config.mjs"
        update_proxy_config_for_dev(proxy_config_path)

        # Now run npm to build the app
        run(["npm", "ci"], cwd=repo_dir)
        run(["npm", "run", "start"], cwd=repo_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print("Branding applied successfully! You can now preview the app at http://localhost:4200")

if __name__ == "__main__":
    main()
