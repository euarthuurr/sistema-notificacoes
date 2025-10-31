from playwright.sync_api import sync_playwright

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    # Tenta carregar o painel diretamente para ver se o servidor se mantém no ar
    # Isso irá falhar se o servidor cair, o que é o nosso teste.
    page.goto("http://localhost:8080/painel.html")
    page.wait_for_load_state("networkidle")

    # Login como admin para garantir que essa funcionalidade não quebrou
    page.goto("http://localhost:8080")
    page.fill("#login", "admin")
    page.fill("#senha", "admin")
    page.click("button[type=submit]")
    page.wait_for_url("**/admin.html")

    # Tira a captura de tela da página de administração
    page.screenshot(path="jules-scratch/verification/admin_page.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
