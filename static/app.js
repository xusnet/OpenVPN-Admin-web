/**
 * OpenVPN Admin — Client-side JS
 * Lightweight, no frameworks.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss flash messages after 5 seconds
  document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => {
      el.style.transition = 'opacity 0.3s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 300);
    }, 5000);
  });

  // Confirm dangerous actions
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', (e) => {
      if (!confirm(el.dataset.confirm || '确定要执行此操作吗？')) {
        e.preventDefault();
      }
    });
  });

  // Auto-refresh for service status page
  const statusEl = document.getElementById('service-status');
  if (statusEl) {
    setInterval(async () => {
      try {
        const resp = await fetch('/api/status');
        const data = await resp.json();
        if (data.success && data.data) {
          const dot = statusEl.querySelector('.status-dot');
          if (data.data.active) {
            dot.className = 'status-dot status-active';
          } else {
            dot.className = 'status-dot status-inactive';
          }
          const clientsEl = document.getElementById('client-count');
          if (clientsEl) {
            clientsEl.textContent = data.data.connected_clients || 0;
          }
        }
      } catch (e) {
        // Silently fail — user can manually refresh
      }
    }, 10000); // every 10 seconds
  }
});
