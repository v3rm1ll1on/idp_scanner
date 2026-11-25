import { $ } from './state.js';

export function initTooltips() {
  const tipEl = document.createElement('div');
  tipEl.className = 'floating-tooltip';
  document.body.appendChild(tipEl);

  let activeTarget = null;

  document.addEventListener('mouseover', (e) => {
    const target = e.target.closest?.('[data-tip]');
    if (!target) return;
    activeTarget = target;
    tipEl.textContent = target.dataset.tip;
    tipEl.style.display = 'block';

    const rect = target.getBoundingClientRect();
    const tipRect = tipEl.getBoundingClientRect();
    let left = rect.left + rect.width / 2 - tipRect.width / 2;
    left = Math.max(8, Math.min(window.innerWidth - tipRect.width - 8, left));

    let top = rect.bottom + 6;
    if (top + tipRect.height > window.innerHeight - 8) {
      top = Math.max(8, rect.top - tipRect.height - 6);
    }

    tipEl.style.left = `${Math.round(left)}px`;
    tipEl.style.top = `${Math.round(top)}px`;
  });

  document.addEventListener('mouseout', (e) => {
    if (!activeTarget) return;
    const related = e.relatedTarget;
    if (!related || !activeTarget.contains(related)) {
      activeTarget = null;
      tipEl.style.display = 'none';
    }
  });
}

export function initResizers() {
  const layout = document.querySelector('.layout');
  const savedSidebar = localStorage.getItem('owb_sidebar_w');
  if (savedSidebar) layout.style.setProperty('--sidebar-w', `${savedSidebar}px`);

  const savedDiagram = localStorage.getItem('owb_diagram_h');
  if (savedDiagram) document.documentElement.style.setProperty('--diagram-h', `${savedDiagram}px`);

  function attachDrag(handle, onMove) {
    if (!handle) return;
    handle.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      handle.classList.add('dragging');
      document.body.style.userSelect = 'none';

      const moveHandler = (ev) => onMove(ev);
      const upHandler = () => {
        handle.classList.remove('dragging');
        document.body.style.userSelect = '';
        window.removeEventListener('pointermove', moveHandler);
        window.removeEventListener('pointerup', upHandler);
      };

      window.addEventListener('pointermove', moveHandler);
      window.addEventListener('pointerup', upHandler);
    });
  }

  attachDrag($('sidebarResizer'), (ev) => {
    const w = Math.max(220, Math.min(560, ev.clientX));
    layout.style.setProperty('--sidebar-w', `${w}px`);
    localStorage.setItem('owb_sidebar_w', String(Math.round(w)));
  });

  const diagramCanvas = $('sequenceDiagram');
  attachDrag($('diagramResizer'), (ev) => {
    const rect = diagramCanvas.getBoundingClientRect();
    const h = Math.max(90, Math.min(460, ev.clientY - rect.top));
    document.documentElement.style.setProperty('--diagram-h', `${h}px`);
    localStorage.setItem('owb_diagram_h', String(Math.round(h)));
  });

  document.querySelectorAll('.split-resizer').forEach((resizer) => {
    const split = resizer.closest('.split-2');
    attachDrag(resizer, (ev) => {
      const rect = split.getBoundingClientRect();
      const pct = Math.max(20, Math.min(80, ((ev.clientX - rect.left) / rect.width) * 100));
      split.style.setProperty('--split-left', `${pct.toFixed(1)}%`);
      split.style.setProperty('--split-right', `${(100 - pct).toFixed(1)}%`);
    });
  });
}

export function initTabsAndHelp() {
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach((c) => c.classList.remove('active'));
      tab.classList.add('active');
      $(`tab-${tab.dataset.tab}`).classList.add('active');
    });
  });

  document.querySelectorAll('.rep-subtab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.rep-subtab').forEach((t) => t.classList.remove('active'));
      document.querySelectorAll('.rep-subpanel').forEach((p) => p.classList.remove('active'));
      tab.classList.add('active');
      $(`reptab-${tab.dataset.reptab}`).classList.add('active');
    });
  });

  document.querySelectorAll('.fuzzer-tab:not(.rep-subtab)').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.fuzzer-tab:not(.rep-subtab)').forEach((t) => t.classList.remove('active'));
      document.querySelectorAll('.fuzzer-panel:not(.rep-subpanel)').forEach((p) => p.classList.remove('active'));
      tab.classList.add('active');
      $(`fuzzer-${tab.dataset.fuzzer}`).classList.add('active');
    });
  });

  const toggleHelp = (show) => {
    $('helpModal').style.display = show ? 'flex' : 'none';
  };
  $('helpBtn').addEventListener('click', () => toggleHelp(true));
  $('closeHelpBtn').addEventListener('click', () => toggleHelp(false));
  $('helpModal').addEventListener('click', (e) => {
    if (e.target === $('helpModal')) toggleHelp(false);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') toggleHelp(false);
    if (e.key === '?' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
      toggleHelp($('helpModal').style.display === 'none');
    }
  });
}
