/* WebSecure – shared client utilities */
document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss flash messages after 5 seconds
  setTimeout(() => {
    document.querySelectorAll('.flash-msg').forEach(el => {
      el.style.transition = 'opacity 0.5s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 500);
    });
  }, 5000);
});
