export function startVisibleRefresh(isActive: () => boolean, refresh: () => void, intervalMs = 5_000) {
  const tick = () => {
    if (document.visibilityState === 'visible' && isActive()) refresh();
  };

  const timer = window.setInterval(tick, intervalMs);
  document.addEventListener('visibilitychange', tick);
  tick();

  return () => {
    window.clearInterval(timer);
    document.removeEventListener('visibilitychange', tick);
  };
}
