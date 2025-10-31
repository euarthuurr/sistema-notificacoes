from playwright.sync_api import sync_playwright

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    # Login como admin
    page.goto("http://localhost:8080")
    page.fill("#login", "admin")
    page.fill("#senha", "admin")
    page.click("button[type=submit]")
    page.wait_for_url("**/admin.html")

    # Tira a captura de tela da página de administração com as estatísticas
    page.screenshot(path="jules-scratch/verification/admin_stats.png")

    # Abre o modal de gerenciamento de usuários
    page.click("button:has-text('Gerenciar Usuários')")

    # Tira a captura de tela do modal com os botões de exportação
    page.screenshot(path="jules-scratch/verification/admin_modal.png")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
