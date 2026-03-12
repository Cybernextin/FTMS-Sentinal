/**
 * FIM Sentinel Login Portal Logic
 */

window.addEventListener('load', () => {
    const flashes = JSON.parse(document.body.dataset.flashes || '[]');
    flashes.forEach(f => {
        // Handle both object-style {category, message} and pair-style [category, message]
        const category = f.category || (Array.isArray(f) ? f[0] : 'info');
        const message = f.message || (Array.isArray(f) ? f[1] : (typeof f === 'string' ? f : ''));

        if (!message) return;

        let toast = document.getElementById('loginToast') || document.getElementById('adminToast');
        let msg = document.getElementById('toastMsg');
        let title = document.getElementById('toastTitle');
        let icon = document.getElementById('toastIcon');

        if (toast && msg) {
            msg.innerText = message;

            // Reset styles for repeated toasts
            if (title) title.style.color = '';
            toast.style.borderColor = '';

            // UI refinements based on category
            if (category === "success") {
                if (title) {
                    title.innerText = "SUCCESS";
                    title.style.color = "#22c55e";
                }
                if (icon) icon.className = "fas fa-check-circle";
                icon.style.color = "#22c55e";
                toast.style.borderColor = "#22c55e";
            } else if (category === "info") {
                if (title) {
                    title.innerText = "NOTICE";
                    title.style.color = "#3b82f6";
                }
                if (icon) icon.className = "fas fa-info-circle";
                icon.style.color = "#3b82f6";
                toast.style.borderColor = "#3b82f6";
            } else {
                // Default to error/warning
                if (title) {
                    title.innerText = "ACCESS DENIED";
                    title.style.color = "#ff3333";
                }
                if (icon) icon.className = "fas fa-shield-exclamation";
                icon.style.color = "#ff3333";
                toast.style.borderColor = "#ff3333";
            }

            toast.style.display = 'flex';
            setTimeout(() => { toast.style.display = 'none'; }, 4000);
        }
    });
});
