(function () {
    function init() {
        const toggle = document.getElementById("toggleForgot");
        const box = document.getElementById("forgotBox");

        if (!toggle || !box) return;

        toggle.addEventListener("click", function () {
            // nếu đang hidden bằng style="display:none"
            const isHidden =
                box.style.display === "none" || getComputedStyle(box).display === "none";

            box.style.display = isHidden ? "block" : "none";
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
