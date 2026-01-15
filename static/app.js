(function(){
  // Preserve selects in URL for alerts filters (if present)
  const sev = document.querySelector('[data-filter="severity"]');
  const st  = document.querySelector('[data-filter="status"]');
  function apply(){
    const url = new URL(window.location.href);
    if (sev) url.searchParams.set("severity", sev.value);
    if (st)  url.searchParams.set("status", st.value);
    window.location.href = url.toString();
  }
  if (sev) sev.addEventListener("change", apply);
  if (st)  st.addEventListener("change", apply);
})();

(function(){
  function resize(ta) {
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = ta.scrollHeight + "px";
  }
  function init() {
    const textareas = document.querySelectorAll("textarea.js-autosize");
    if (!textareas.length) return;
    textareas.forEach(function(ta) {
      resize(ta);
      ta.addEventListener("input", function(){ resize(ta); });
    });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

(function(){
  function applyCondense(table, enabled) {
    const rows = table.querySelectorAll("tbody tr[data-alert-id]");
    const seen = {};
    rows.forEach(function(row) {
      const id = row.getAttribute("data-alert-id");
      if (!id) return;
      if (enabled) {
        if (seen[id]) {
          row.style.display = "none";
        } else {
          row.style.display = "";
          seen[id] = true;
        }
      } else {
        row.style.display = "";
      }
    });
  }
  function init() {
    const toggle = document.querySelector(".js-condense-toggle");
    const table = document.querySelector('[data-weekly-table="events"]');
    if (!toggle || !table) return;
    function update() { applyCondense(table, toggle.checked); }
    toggle.addEventListener("change", update);
    update();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
