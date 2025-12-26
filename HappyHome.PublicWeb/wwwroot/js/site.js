function toggleMenu() {
    const menu = document.getElementById("mainMenu");
    const btn = document.querySelector(".hamburger");
    const expanded = btn.getAttribute("aria-expanded") === "true";
    btn.setAttribute("aria-expanded", String(!expanded));
    menu.classList.toggle("is-open");
}