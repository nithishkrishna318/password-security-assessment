document.addEventListener("click", function (event) {
  const button = event.target.closest("[data-toggle-password]");
  if (!button) return;
  const input = document.getElementById(button.dataset.togglePassword);
  if (!input) return;
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  button.textContent = show ? "Hide" : "Show";
});
