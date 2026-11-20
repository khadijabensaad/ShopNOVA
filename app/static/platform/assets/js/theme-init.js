// Chargé de façon synchrone dans <head> : applique le thème AVANT le premier rendu (aucun flash).
(function () {
  try {
    var pref = localStorage.getItem('snv-theme') || 'system';
    var dark = pref === 'dark' || (pref === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    if (localStorage.getItem('snv-reduce-motion') === '1') document.documentElement.classList.add('reduce-motion');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();
