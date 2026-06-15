/**
 * OpenVPN Admin — Client-side JS
 * Lightweight, no frameworks.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss flash messages. Success/info messages fade after 5s;
  // warnings/errors stick around longer (8s) so the operator can read
  // them. Hovering the message pauses the countdown.
  document.querySelectorAll('.flash').forEach(el => {
    const isCritical = el.classList.contains('flash-danger')
                     || el.classList.contains('flash-warning');
    const delay = isCritical ? 8000 : 5000;
    let timer = setTimeout(() => fadeOut(el), delay);

    el.addEventListener('mouseenter', () => clearTimeout(timer));
    el.addEventListener('mouseleave', () => {
      timer = setTimeout(() => fadeOut(el), 2000);
    });
  });

  // Confirm dangerous actions
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', (e) => {
      if (!confirm(el.dataset.confirm || '确定要执行此操作吗？')) {
        e.preventDefault();
      }
    });
  });
});

function fadeOut(el) {
  el.style.transition = 'opacity 0.3s';
  el.style.opacity = '0';
  setTimeout(() => el.remove(), 300);
}
