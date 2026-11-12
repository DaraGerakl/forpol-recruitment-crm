
document.addEventListener('DOMContentLoaded', function () {
  // Lucide falls back to simple symbols if the CDN is unreachable.
  document.querySelectorAll('.navicon[data-icon]').forEach(function (el) {
    el.setAttribute('data-lucide', el.getAttribute('data-icon'));
  });
  var icons = ['truck', 'package', 'warehouse', 'scan-barcode', 'layers-3', 'boxes', 'forklift', 'container'];
  var cards = Array.from(document.querySelectorAll('[data-vacancy]'));
  function statusKind(s) {
    s = (s || '').toLowerCase().trim();
    if (/пауз|pause|pending|ожидан/.test(s)) return 'paused';
    if (/неактив|закры|архив|inactive|closed|draft|отмен/.test(s)) return 'inactive';
    if (/актив|откры|active|набор/.test(s)) return 'active';
    return 'inactive';
  }
  cards.forEach(function(card, index) {
    var kind = statusKind(card.dataset.status);
    card.dataset.kind = kind;
    var badge = card.querySelector('[data-status-badge]');
    if (badge) badge.classList.add('is-' + kind);
    var icon = card.querySelector('[data-job-icon] i');
    if (icon) {
      var key = (card.dataset.search || '').toLowerCase();
      var selected = /скан|scanner/.test(key) ? 'scan-barcode' :
        /достав|курьер|водител|driver/.test(key) ? 'truck' :
        /сортир|посыл|почт|inpost|dpd/.test(key) ? 'package' :
        /одежд|упаков|комплект/.test(key) ? 'layers-3' :
        /склад|warehouse|magazyn/.test(key) ? 'warehouse' :
        icons[index % icons.length];
      icon.setAttribute('data-lucide', selected);
    }
  });
  function renderIcons() {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    } else {
      document.querySelectorAll('[data-lucide]').forEach(function(el) {
        if (!el.querySelector('svg') && !el.textContent.trim()) el.textContent = '◻';
      });
    }
  }
  renderIcons();
  var search = document.getElementById('vac-search');
  var filters = Array.from(document.querySelectorAll('.vac-filter'));
  if (!search || !filters.length) return;
  ['all', 'active', 'paused', 'inactive'].forEach(function(kind) {
    var count = document.getElementById('count-' + kind);
    if (count) count.textContent = kind === 'all' ? cards.length : cards.filter(function(c){return c.dataset.kind === kind}).length;
  });
  var selected = 'all';
  function update() {
    var q = search.value.toLowerCase().trim();
    var visible = 0;
    cards.forEach(function(card) {
      var match = (selected === 'all' || card.dataset.kind === selected) &&
        (!q || (card.dataset.search || '').toLowerCase().includes(q));
      card.hidden = !match;
      if (match) visible++;
    });
    var noResults = document.getElementById('vac-no-results');
    if (noResults) noResults.hidden = visible > 0 || cards.length === 0;
    var count = document.getElementById('vac-visible-count');
    if (count) count.textContent = 'Показано: ' + visible;
  }
  filters.forEach(function(btn) {
    btn.addEventListener('click', function() {
      selected = btn.dataset.filter;
      filters.forEach(function(b){b.classList.toggle('is-selected', b === btn)});
      update();
    });
  });
  search.addEventListener('input', update);
  update();
});
