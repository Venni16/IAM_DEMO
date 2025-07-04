// DOM Elements
const loginContainer = document.getElementById("login-container")
const dashboardContainer = document.getElementById("dashboard-container")
const loginBtn = document.getElementById("login-btn")
const logoutBtn = document.getElementById("logout-btn")
const usernameInput = document.getElementById("username")
const passwordInput = document.getElementById("password")
const loginError = document.getElementById("login-error")
const loginLockoutInfo = document.getElementById("login-lockout-info")
const userName = document.getElementById("user-name")
const userRole = document.getElementById("user-role")
const profileUsername = document.getElementById("profile-username")
const profileName = document.getElementById("profile-name")
const profileRole = document.getElementById("profile-role")
const profileInitial = document.getElementById("profile-initial")
const adminElements = document.querySelectorAll(".admin-only")
const navLinks = document.querySelectorAll(".nav-link")
const contentSections = document.querySelectorAll(".content-section")
const usersTableBody = document.getElementById("users-table-body")
const logsTableBody = document.getElementById("logs-table-body")
const loginAttemptsTableBody = document.getElementById("login-attempts-table-body")
const blacklistTableBody = document.getElementById("blacklist-table-body")
const addUserBtn = document.getElementById("add-user-btn")
const addBlacklistBtn = document.getElementById("add-blacklist-btn")
const userModal = document.getElementById("user-modal")
const blacklistModal = document.getElementById("blacklist-modal")
const userForm = document.getElementById("user-form")
const blacklistForm = document.getElementById("blacklist-form")
const closeModalBtn = document.getElementById("close-modal")
const closeBlacklistModalBtn = document.getElementById("close-blacklist-modal")
const modalTitle = document.getElementById("modal-title")
const modalSubmitBtn = document.getElementById("modal-submit")
const modalDeleteBtn = document.getElementById("modal-delete")
const confirmationModal = document.getElementById("confirmation-modal")
const confirmDeleteBtn = document.getElementById("confirm-delete")
const cancelDeleteBtn = document.getElementById("cancel-delete")

// Current user data
let currentUser = null
let editingUser = null
let lockoutTimer = null

// Check if user is already logged in
function checkAuthStatus() {
  fetch("/user/profile")
    .then((response) => {
      if (response.ok) {
        return response.json()
      }
      throw new Error("Not authenticated")
    })
    .then((data) => {
      currentUser = {
        username: data.username,
        role: data.role,
        name: data.name,
      }
      showDashboard()
    })
    .catch((error) => {
      showLogin()
    })
}

// Login function
function login() {
  const username = usernameInput.value.trim()
  const password = passwordInput.value.trim()

  if (!username || !password) {
    loginError.textContent = "Please enter both username and password"
    return
  }

  loginError.textContent = ""
  loginLockoutInfo.textContent = ""
  loginLockoutInfo.classList.add("hidden")

  // Clear any existing lockout timer
  if (lockoutTimer) {
    clearInterval(lockoutTimer)
    lockoutTimer = null
  }

  fetch("/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  })
    .then((response) => {
      if (response.status === 403 && response.headers.get("Content-Type").includes("application/json")) {
        return response.json().then((data) => {
          if (data.blacklisted) {
            throw new Error("IP_BLACKLISTED")
          }
          return data
        })
      }
      return response.json()
    })
    .then((data) => {
      if (data.error) {
        loginError.textContent = data.error

        // Handle account lockout
        if (data.locked) {
          handleAccountLockout(data.lockout_remaining)
        }
      } else {
        currentUser = data.user
        showDashboard()
      }
    })
    .catch((error) => {
      if (error.message === "IP_BLACKLISTED") {
        loginError.textContent = "Access denied. Your IP address has been blacklisted due to suspicious activity."
      } else {
        loginError.textContent = "An error occurred. Please try again."
        console.error("Login error:", error)
      }
    })
}

// Handle account lockout UI
function handleAccountLockout(remainingSeconds) {
  loginLockoutInfo.classList.remove("hidden")

  // Update lockout message
  updateLockoutMessage(remainingSeconds)

  // Set up countdown timer
  lockoutTimer = setInterval(() => {
    remainingSeconds--

    if (remainingSeconds <= 0) {
      clearInterval(lockoutTimer)
      loginLockoutInfo.classList.add("hidden")
      loginError.textContent = "Your account is now unlocked. Please try again."
    } else {
      updateLockoutMessage(remainingSeconds)
    }
  }, 1000)
}

// Update lockout message with time remaining
function updateLockoutMessage(remainingSeconds) {
  const minutes = Math.floor(remainingSeconds / 60)
  const seconds = remainingSeconds % 60
  loginLockoutInfo.textContent = `Account is temporarily locked. Please try again in ${minutes}:${seconds.toString().padStart(2, "0")}.`
}

// Logout function
function logout() {
  fetch("/logout", {
    method: "POST",
  })
    .then(() => {
      currentUser = null
      showLogin()
    })
    .catch((error) => {
      console.error("Logout error:", error)
    })
}

// Show login screen
function showLogin() {
  loginContainer.classList.remove("hidden")
  dashboardContainer.classList.add("hidden")
  usernameInput.value = ""
  passwordInput.value = ""
  loginError.textContent = ""
  loginLockoutInfo.classList.add("hidden")
}

// Show dashboard
function showDashboard() {
  loginContainer.classList.add("hidden")
  dashboardContainer.classList.remove("hidden")

  // Update user info
  userName.textContent = currentUser.name
  userRole.textContent = currentUser.role

  // Update profile section
  profileUsername.textContent = currentUser.username
  profileName.textContent = currentUser.name
  profileRole.textContent = currentUser.role
  profileInitial.textContent = currentUser.name.charAt(0)

  // Show/hide admin sections
  if (currentUser.role === "admin") {
    adminElements.forEach((el) => el.classList.remove("hidden"))
    loadUsers()
    loadLogs()
    loadLoginAttempts()
    loadBlacklist()
  } else {
    adminElements.forEach((el) => el.classList.add("hidden"))
  }

  // Activate first visible nav link
  const firstVisibleLink = document.querySelector(".nav-link:not(.hidden)")
  if (firstVisibleLink) {
    activateNavLink(firstVisibleLink)
  }
}

// Load users (admin only)
function loadUsers() {
  fetch("/admin/users")
    .then((response) => {
      if (response.ok) {
        return response.json()
      }
      throw new Error("Failed to load users")
    })
    .then((data) => {
      usersTableBody.innerHTML = ""
      data.users.forEach((user) => {
        const row = document.createElement("tr")

        // Add locked status indicator
        const lockedStatus = user.locked ? `<span class="badge locked-badge">Locked</span>` : ""

        // Create unlock button if account is locked
        const unlockButton = user.locked
          ? `<button class="btn action-btn unlock-user" data-username="${user.username}" title="Unlock Account">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
             </button>`
          : ""

        row.innerHTML = `
          <td>${user.username} ${lockedStatus}</td>
          <td>${user.name}</td>
          <td><span class="badge" style="background-color: ${user.role === "admin" ? "#ef4444" : "#3b82f6"}">${user.role}</span></td>
          <td>${user.failed_attempts} ${user.locked ? `(${Math.ceil(user.lockout_remaining / 60)} min)` : ""}</td>
          <td class="actions">
            ${unlockButton}
            <button class="btn action-btn edit-user" data-username="${user.username}" data-name="${user.name}" data-role="${user.role}">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
            </button>
            <button class="btn action-btn delete-user" data-username="${user.username}" ${user.username === currentUser.username ? "disabled" : ""}>
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
            </button>
          </td>
        `
        usersTableBody.appendChild(row)
      })

      // Add event listeners to edit and delete buttons
      document.querySelectorAll(".edit-user").forEach((btn) => {
        btn.addEventListener("click", () => {
          const row = btn.closest("tr");
          const username = btn.getAttribute("data-username")
          const name = btn.getAttribute("data-name")
          const role = btn.getAttribute("data-role")
          openEditUserModal(username, name, role)
        })
      })

      document.querySelectorAll(".delete-user").forEach((btn) => {
        btn.addEventListener("click", () => {
          const username = btn.getAttribute("data-username")
          openDeleteConfirmation(username)
        })
      })

      // Add event listeners to unlock buttons
      document.querySelectorAll(".unlock-user").forEach((btn) => {
        btn.addEventListener("click", () => {
          const username = btn.getAttribute("data-username")
          unlockUser(username)
        })
      })
    })
    .catch((error) => {
      console.error("Error loading users:", error)
      showNotification("Failed to load users", "error")
    })
}

// Unlock a user account
function unlockUser(username) {
  fetch(`/admin/unlock-user/${username}`, {
    method: "POST",
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) {
        showNotification(data.error, "error")
      } else {
        showNotification(`Account for ${username} has been unlocked`, "success")
        loadUsers()
      }
    })
    .catch((error) => {
      console.error("Error unlocking user:", error)
      showNotification("Failed to unlock user account", "error")
    })
}

// Load security logs (admin only)
function loadLogs() {
  fetch("/admin/logs")
    .then((response) => {
      if (response.ok) {
        return response.json()
      }
      throw new Error("Failed to load logs")
    })
    .then((data) => {
      logsTableBody.innerHTML = ""
      data.logs.forEach((log) => {
        const row = document.createElement("tr")
        const timestamp = new Date(log.timestamp).toLocaleString()
        const levelColor = getLevelColor(log.level)

        row.innerHTML = `
          <td>${timestamp}</td>
          <td>${log.message}</td>
          <td><span class="badge" style="background-color: ${levelColor}">${log.level}</span></td>
        `
        logsTableBody.appendChild(row)
      })
    })
    .catch((error) => {
      console.error("Error loading logs:", error)
      showNotification("Failed to load security logs", "error")
    })
}

// Load login attempts (admin only)
function loadLoginAttempts() {
  if (!loginAttemptsTableBody) return

  fetch("/admin/login-attempts")
    .then((response) => {
      if (response.ok) {
        return response.json()
      }
      throw new Error("Failed to load login attempts")
    })
    .then((data) => {
      loginAttemptsTableBody.innerHTML = ""
      data.login_attempts.forEach((attempt) => {
        const row = document.createElement("tr")
        const timestamp = new Date(attempt.timestamp).toLocaleString()
        const successBadge = attempt.success
          ? '<span class="badge" style="background-color: #10b981">Success</span>'
          : '<span class="badge" style="background-color: #ef4444">Failed</span>'

        row.innerHTML = `
          <td>${timestamp}</td>
          <td>${attempt.username}</td>
          <td>${attempt.ip_address}</td>
          <td>${successBadge}</td>
          <td class="actions">
            <button class="btn action-btn blacklist-ip" data-ip="${attempt.ip_address}" title="Blacklist IP">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>
            </button>
          </td>
        `
        loginAttemptsTableBody.appendChild(row)
      })

      // Add event listeners to blacklist buttons
      document.querySelectorAll(".blacklist-ip").forEach((btn) => {
        btn.addEventListener("click", () => {
          const ip = btn.getAttribute("data-ip")
          openBlacklistModal(ip)
        })
      })
    })
    .catch((error) => {
      console.error("Error loading login attempts:", error)
      showNotification("Failed to load login attempts", "error")
    })
}

// Load IP blacklist (admin only)
function loadBlacklist() {
  if (!blacklistTableBody) return

  fetch("/admin/blacklist")
    .then((response) => {
      if (response.ok) {
        return response.json()
      }
      throw new Error("Failed to load blacklist")
    })
    .then((data) => {
      blacklistTableBody.innerHTML = ""
      data.blacklist.forEach((entry) => {
        const row = document.createElement("tr")
        const createdAt = new Date(entry.created_at).toLocaleString()

        // Format expiry time
        let expiryText = "Never (Permanent)"
        if (entry.expires_at) {
          const expiryDate = new Date(entry.expires_at).toLocaleString()
          const remainingHours = Math.ceil(entry.expiry_remaining / 3600)
          expiryText = `${expiryDate} (${remainingHours} hours remaining)`
        }

        row.innerHTML = `
          <td>${entry.ip_address}</td>
          <td>${entry.reason}</td>
          <td>${createdAt}</td>
          <td>${expiryText}</td>
          <td class="actions">
            <button class="btn action-btn remove-blacklist" data-id="${entry.id}" title="Remove from Blacklist">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="8" y1="12" x2="16" y2="12"></line></svg>
            </button>
          </td>
        `
        blacklistTableBody.appendChild(row)
      })

      // Add event listeners to remove buttons
      document.querySelectorAll(".remove-blacklist").forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = btn.getAttribute("data-id")
          removeFromBlacklist(id)
        })
      })
    })
    .catch((error) => {
      console.error("Error loading blacklist:", error)
      showNotification("Failed to load IP blacklist", "error")
    })
}

// Remove IP from blacklist
function removeFromBlacklist(id) {
  fetch(`/admin/blacklist/${id}`, {
    method: "DELETE",
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) {
        showNotification(data.error, "error")
      } else {
        showNotification("IP address removed from blacklist", "success")
        loadBlacklist()
      }
    })
    .catch((error) => {
      console.error("Error removing from blacklist:", error)
      showNotification("Failed to remove IP from blacklist", "error")
    })
}

// Open blacklist modal
function openBlacklistModal(ip = "") {
  document.getElementById("blacklist-ip").value = ip
  document.getElementById("blacklist-reason").value = ip ? `Suspicious activity from IP: ${ip}` : ""
  document.getElementById("blacklist-hours").value = "24"
  blacklistModal.classList.remove("hidden")
}

// Close blacklist modal
function closeBlacklistModal() {
  blacklistModal.classList.add("hidden")
  blacklistForm.reset()
}

// Submit blacklist form
function submitBlacklistForm(e) {
  e.preventDefault()

  const formData = new FormData(blacklistForm)
  const blacklistData = {
    ip_address: formData.get("ip_address"),
    reason: formData.get("reason"),
  }

  // Handle expiration
  const isPermanent = formData.get("permanent") === "on"
  if (!isPermanent) {
    const hours = Number.parseInt(formData.get("hours"), 10)
    if (!isNaN(hours) && hours > 0) {
      blacklistData.hours = hours
    }
  }

  // Add IP to blacklist
  fetch("/admin/blacklist", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(blacklistData),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) {
        showNotification(data.error, "error")
      } else {
        showNotification("IP address blacklisted successfully", "success")
        closeBlacklistModal()
        loadBlacklist()
      }
    })
    .catch((error) => {
      console.error("Error blacklisting IP:", error)
      showNotification("Failed to blacklist IP address", "error")
    })
}

// Get color for log level
function getLevelColor(level) {
  switch (level.toLowerCase()) {
    case "info":
      return "#3b82f6"
    case "warning":
      return "#f59e0b"
    case "error":
      return "#ef4444"
    default:
      return "#6b7280"
  }
}

// Open modal to add a new user
function openAddUserModal() {
  modalTitle.textContent = "Add New User"
  userForm.reset()
  document.getElementById("username-field").disabled = false
  document.getElementById("password-field").required = true
  document.getElementById("password-label").textContent = "Password *"
  modalSubmitBtn.textContent = "Create User"
  modalDeleteBtn.classList.add("hidden")
  editingUser = null
  userModal.classList.remove("hidden")
}

// Open modal to edit an existing user
function openEditUserModal(username, name, role) {
  modalTitle.textContent = "Edit User"
  document.getElementById("username-field").value = username
  document.getElementById("username-field").disabled = true
  document.getElementById("name-field").value = name
  document.getElementById("role-field").value = role
  document.getElementById("password-field").required = false
  document.getElementById("password-field").value = ""
  document.getElementById("password-label").textContent = "Password (leave blank to keep current)"
  modalSubmitBtn.textContent = "Update User"
  modalDeleteBtn.classList.remove("hidden")
  editingUser = username
  userModal.classList.remove("hidden")
}

// Close the user modal
function closeUserModal() {
  userModal.classList.add("hidden")
  userForm.reset()
}

// Open delete confirmation modal
function openDeleteConfirmation(username) {
  document.getElementById("confirm-message").textContent = `Are you sure you want to delete user "${username}"?`
  confirmDeleteBtn.setAttribute("data-username", username)
  confirmationModal.classList.remove("hidden")
}

// Close delete confirmation modal
function closeDeleteConfirmation() {
  confirmationModal.classList.add("hidden")
}

// Submit user form (create or update)
function submitUserForm(e) {
  e.preventDefault()

  const formData = new FormData(userForm)
  const userData = {
    username: formData.get("username"),
    name: formData.get("name"),
    role: formData.get("role"),
  }

  // Only include password if it's provided
  const password = formData.get("password")
  if (password) {
    userData.password = password
  }

  // Include unlock flag if checkbox is checked
  if (formData.get("unlock_account")) {
    userData.unlock = true
  }

  if (editingUser) {
    // Update existing user
    updateUser(editingUser, userData)
  } else {
    // Create new user
    createUser(userData)
  }
}

// Create a new user
function createUser(userData) {
  fetch("/admin/users", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(userData),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) {
        showNotification(data.error, "error")
      } else {
        showNotification("User created successfully", "success")
        closeUserModal()
        loadUsers()
      }
    })
    .catch((error) => {
      console.error("Error creating user:", error)
      showNotification("Failed to create user", "error")
    })
}

// Update an existing user
function updateUser(username, userData) {
  fetch(`/admin/users/${username}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(userData),
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) {
        showNotification(data.error, "error")
      } else {
        showNotification("User updated successfully", "success")
        closeUserModal()
        loadUsers()

        // If current user was updated, refresh profile
        if (username === currentUser.username) {
          checkAuthStatus()
        }
      }
    })
    .catch((error) => {
      console.error("Error updating user:", error)
      showNotification("Failed to update user", "error")
    })
}

// Delete a user
function deleteUser(username) {
  fetch(`/admin/users/${username}`, {
    method: "DELETE",
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) {
        showNotification(data.error, "error")
      } else {
        showNotification("User deleted successfully", "success")
        closeDeleteConfirmation()
        loadUsers()
      }
    })
    .catch((error) => {
      console.error("Error deleting user:", error)
      showNotification("Failed to delete user", "error")
    })
}

// Show notification
function showNotification(message, type = "info") {
  const notification = document.createElement("div")
  notification.className = `notification ${type}`
  notification.textContent = message

  document.body.appendChild(notification)

  // Show notification
  setTimeout(() => {
    notification.classList.add("show")
  }, 10)

  // Hide and remove notification after 3 seconds
  setTimeout(() => {
    notification.classList.remove("show")
    setTimeout(() => {
      document.body.removeChild(notification)
    }, 300)
  }, 3000)
}

// Toggle permanent blacklist option
function toggleBlacklistDuration() {
  const isPermanent = document.getElementById("blacklist-permanent").checked
  const hoursField = document.getElementById("blacklist-hours")
  const hoursLabel = document.querySelector('label[for="blacklist-hours"]')

  if (isPermanent) {
    hoursField.disabled = true
    hoursField.parentElement.classList.add("disabled")
  } else {
    hoursField.disabled = false
    hoursField.parentElement.classList.remove("disabled")
  }
}

// Navigation
function activateNavLink(link) {
  // Deactivate all links
  navLinks.forEach((navLink) => {
    navLink.classList.remove("active")
  })

  // Hide all sections
  contentSections.forEach((section) => {
    section.classList.add("hidden")
  })

  // Activate clicked link
  link.classList.add("active")

  // Show corresponding section
  const targetId = link.getAttribute("data-target")
  const targetSection = document.getElementById(targetId)
  if (targetSection) {
    targetSection.classList.remove("hidden")
  }
}

// Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  // Check if user is already logged in
  checkAuthStatus()

  // Login button
  loginBtn.addEventListener("click", login)

  // Enter key in password field
  passwordInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      login()
    }
  })

  // Logout button
  logoutBtn.addEventListener("click", logout)

  // Navigation links
  navLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault()
      activateNavLink(link)
    })
  })

  // Add user button
  if (addUserBtn) {
    addUserBtn.addEventListener("click", openAddUserModal)
  }

  // Add blacklist button
  if (addBlacklistBtn) {
    addBlacklistBtn.addEventListener("click", () => openBlacklistModal())
  }

  // Close modal buttons
  if (closeModalBtn) {
    closeModalBtn.addEventListener("click", closeUserModal)
  }

  if (closeBlacklistModalBtn) {
    closeBlacklistModalBtn.addEventListener("click", closeBlacklistModal)
  }

  // Form submissions
  if (userForm) {
    userForm.addEventListener("submit", submitUserForm)
  }

  if (blacklistForm) {
    blacklistForm.addEventListener("submit", submitBlacklistForm)
  }

  // Permanent blacklist toggle
  const permanentCheckbox = document.getElementById("blacklist-permanent")
  if (permanentCheckbox) {
    permanentCheckbox.addEventListener("change", toggleBlacklistDuration)
  }

  // Modal delete button
  if (modalDeleteBtn) {
    modalDeleteBtn.addEventListener("click", (e) => {
      e.preventDefault()
      if (editingUser) {
        openDeleteConfirmation(editingUser)
      }
    })
  }

  // Confirm delete button
  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener("click", () => {
      const username = confirmDeleteBtn.getAttribute("data-username")
      if (username) {
        deleteUser(username)
      }
    })
  }

  // Cancel delete button
  if (cancelDeleteBtn) {
    cancelDeleteBtn.addEventListener("click", closeDeleteConfirmation)
  }

  // Close modals when clicking outside
  window.addEventListener("click", (e) => {
    if (e.target === userModal) {
      closeUserModal()
    }
    if (e.target === blacklistModal) {
      closeBlacklistModal()
    }
    if (e.target === confirmationModal) {
      closeDeleteConfirmation()
    }
  })
})