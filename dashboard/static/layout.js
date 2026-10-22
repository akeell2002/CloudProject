(() => {
  "use strict";

  const $ = (selector) => document.querySelector(selector);

  document.body.classList.add("studio-light");

  const main = $(".main");
  const topology = $(".topology-area");
  const inspector = $(".inspector");
  const scroller = $("#scroller");
  const canvas = $("#canvas");

  // Build the three-column layout.
  const shell = document.createElement("div");
  shell.className = "studio-shell";

  const left = document.createElement("aside");
  left.className = "studio-left";
  left.setAttribute("aria-label", "Project metrics");

  const brand = document.createElement("div");
  brand.className = "studio-brand";
  brand.innerHTML = `
    <span class="studio-logo">◈</span>
    <strong>CloudProject</strong>
    <small>Network Studio</small>
  `;

  left.append(brand, $(".metrics"));

  const navigation = document.createElement("div");
  navigation.className = "studio-navigation";
  navigation.append($("#navEvents"), $("#navRecords"));
  left.append(navigation);

  const right = document.createElement("aside");
  right.className = "studio-right";
  right.setAttribute("aria-label", "Controls and activity");

  right.append($(".top-controls"));

  const activityTitle = document.createElement("h2");
  activityTitle.className = "activity-title";
  activityTitle.textContent = "Pipeline activity";

  right.append(
    activityTitle,
    $(".inspector-tabs"),
    $("#eventsPanel"),
    $("#recordsPanel")
  );

  const demoControls = $(".footer-right");
  right.append(demoControls);

  // Reuse the existing inspector content as a floating popup.
  inspector.classList.add("node-popup");
  inspector.hidden = true;
  inspector.setAttribute("role", "dialog");
  inspector.setAttribute("aria-labelledby", "inspectTitle");
  inspector.setAttribute("tabindex", "-1");

  const close = document.createElement("button");
  close.type = "button";
  close.className = "popup-close";
  close.textContent = "×";
  close.setAttribute("aria-label", "Close component details");

  $(".inspector-heading").append(close);
  topology.append(inspector);

  shell.append(left, topology, right);

  // Move the new layout into the existing main element.
  main.prepend(shell);

  // Remove only the empty/replaced layout wrappers.
  $(".rail").remove();
  $(".topbar").remove();
  $(".workspace").remove();

  const stageTitle = $(".stage-bar .overline");
  stageTitle.textContent = "DISTRIBUTED PIPELINE";

  // Node selection still uses the original app.js handlers.
  // This delegated handler only opens and positions the popup.
  let lastNodeKey = null;

  function placePopup(node) {
    const area = topology.getBoundingClientRect();
    const anchor = node.getBoundingClientRect();

    const width = inspector.offsetWidth;
    const height = inspector.offsetHeight;

    let x = anchor.right - area.left + 12;
    let y = anchor.top - area.top;

    if (x + width > area.width - 12) {
      x = anchor.left - area.left - width - 12;
    }

    x = Math.max(12, Math.min(x, area.width - width - 12));
    y = Math.max(12, Math.min(y, area.height - height - 12));

    inspector.style.left = `${x}px`;
    inspector.style.top = `${y}px`;
  }

  function closePopup(restoreFocus = false) {
    inspector.hidden = true;

    if (restoreFocus && lastNodeKey) {
      // Worker buttons are recreated by app.js, so find the current one.
      const node = Array.from(
        topology.querySelectorAll("[data-node]")
      ).find((item) => item.dataset.node === lastNodeKey);

      node?.focus({ preventScroll: true });
    }
  }

  topology.addEventListener("click", (event) => {
    const node = event.target.closest(".graph-node, .worker-row");

    if (node) {
      lastNodeKey = node.dataset.node;
      inspector.hidden = false;
      placePopup(node);
      close.focus({ preventScroll: true });
      return;
    }

    if (
      !event.target.closest(".node-popup") &&
      event.target.closest(".canvas-scroller")
    ) {
      closePopup();
    }
  });

  close.addEventListener("click", () => closePopup(true));

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !inspector.hidden) {
      closePopup(true);
    }
  });

  scroller.addEventListener("scroll", () => closePopup());

  // Keep the SVG connections and HTML nodes scaled together.
  // The spacer provides the correct scrollable dimensions.
  const spacer = document.createElement("div");
  spacer.className = "canvas-spacer";
  canvas.before(spacer);
  spacer.append(canvas);

  let zoom = 1;
  let automaticFit = true;

  function applyZoom(value) {
    zoom = Math.max(0.2, Math.min(1.6, value));

    canvas.style.transform = `scale(${zoom})`;
    spacer.style.width = `${1160 * zoom}px`;
    spacer.style.height = `${Number(canvas.dataset.height || 660) * zoom}px`;

    $("#zoomPct").textContent = `${Math.round(zoom * 100)}%`;
    closePopup();
  }

  function fitCanvas() {
    const width = Math.max(1, scroller.clientWidth - 32);
    const height = Math.max(1, scroller.clientHeight - 32);

    applyZoom(Math.min(width / 1160, height / Number(canvas.dataset.height || 660), 1));
  }

  // Replace the zoom buttons to remove their previous handlers.
  // The original app's data and simulation handlers remain untouched.
  function wireZoom(id, action) {
    const oldButton = document.getElementById(id);
    const button = oldButton.cloneNode(true);
    oldButton.replaceWith(button);
    button.addEventListener("click", action);
  }

  wireZoom("zoomIn", () => {
    automaticFit = false;
    applyZoom(zoom + 0.1);
  });

  wireZoom("zoomOut", () => {
    automaticFit = false;
    applyZoom(zoom - 0.1);
  });

  wireZoom("zoomReset", () => {
    automaticFit = true;
    fitCanvas();
  });

  $("#zoomReset").title = "Fit topology to canvas";

  new ResizeObserver(() => {
    closePopup();
    if (automaticFit) fitCanvas();
  }).observe(scroller);

  window.addEventListener('topology-resized', () => {
    if (automaticFit) fitCanvas();
    else applyZoom(zoom);
  });
  requestAnimationFrame(fitCanvas);
})();