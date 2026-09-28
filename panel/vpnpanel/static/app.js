// Copy buttons, delete confirmation, auto-submit of filters. Everything works without JS too.
document.addEventListener("click", function (ev) {
  var b = ev.target.closest("[data-copy]");
  if (!b) return;
  var el = document.getElementById(b.getAttribute("data-copy"));
  if (!el) return;
  var done = function () { var t = b.textContent; b.textContent = "Скопировано"; setTimeout(function () { b.textContent = t; }, 1500); };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(el.value).then(done);
  } else {
    el.select(); document.execCommand("copy"); done();
  }
});
document.addEventListener("click", function (ev) {
  var b = ev.target.closest("[data-copy-text]");
  if (!b) return;
  var el = document.getElementById(b.getAttribute("data-copy-text"));
  if (!el) return;
  var t = b.textContent;
  var done = function () { b.textContent = "скопировано"; setTimeout(function () { b.textContent = t; }, 1500); };
  if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(el.textContent).then(done); }
});
document.addEventListener("submit", function (ev) {
  var msg = ev.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) ev.preventDefault();
});
document.querySelectorAll(".filters select").forEach(function (s) {
  s.addEventListener("change", function () { s.form.submit(); });
});
