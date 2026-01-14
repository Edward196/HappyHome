(function () {
    document.addEventListener("DOMContentLoaded", function () {
        const newPwd = document.getElementById("newPassword");
        const confirmPwd = document.getElementById("confirmPassword");
        const err = document.getElementById("clientError");
        const btn = document.getElementById("submitBtn");

        if (!newPwd || !confirmPwd || !err) return;

        function showError(text) {
            err.style.display = "block";
            err.textContent = text;
        }

        function clearError() {
            err.style.display = "none";
            err.textContent = "";
        }

        // chặn submit nếu confirm không khớp
        const form = btn?.closest("form");
        if (form) {
            form.addEventListener("submit", function (e) {
                clearError();

                const a = (newPwd.value || "").trim();
                const b = (confirmPwd.value || "").trim();

                if (a.length < 6) {
                    e.preventDefault();
                    showError("Mật khẩu mới phải tối thiểu 6 ký tự.");
                    newPwd.focus();
                    return;
                }

                if (a !== b) {
                    e.preventDefault();
                    showError("Mật khẩu nhập lại không khớp.");
                    confirmPwd.focus();
                    return;
                }
            });
        }
    });
})();
