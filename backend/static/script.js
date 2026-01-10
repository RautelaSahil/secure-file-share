//    TOAST HELPER
function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add("show"));

  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

//    UPLOAD LOGIC
async function uploadFile() {
  const fileInput = document.getElementById("fileInput");
  const uploadBtn = document.getElementById("uploadBtn");

  if (!fileInput.files.length) {
    showToast("Please select a file", "error");
    return;
  }

  uploadBtn.disabled = true;

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  try {
    const res = await fetch("/upload", {
      method: "POST",
      body: formData
    });

    const data = await res.json();
    uploadBtn.disabled = false;

    if (res.ok) {
      showToast(data.message || "File uploaded successfully", "success");
      fileInput.value = "";
      loadMyFiles();
    } else {
      if (res.status === 401) {
        showToast("Session expired. Please log in again.", "error");
        setTimeout(() => window.location.href = "/login", 1200);
      } else {
        showToast(data.error || "Upload failed", "error");
      }
    }

  } catch {
    uploadBtn.disabled = false;
    showToast("Network error", "error");
  }
}

//    LOAD RECENT FILES
async function loadMyFiles() {
  const list = document.getElementById("fileList");
  if (!list) return;

  list.innerHTML = "";

  try {
    const res = await fetch("/api/files/my");
    if (!res.ok) return;

    const files = await res.json();
    if (!files.length) {
      list.innerHTML = "<li>No uploads yet</li>";
      return;
    }

    files.forEach(file => {
      const li = document.createElement("li");
      li.textContent = `${file.original_filename} (${new Date(file.uploaded_at).toLocaleString()})`;
      list.appendChild(li);
    });

  } catch {
    showToast("Failed to load files", "error");
  }
}

//    INIT
document.addEventListener("DOMContentLoaded", () => {
  loadMyFiles();
});
