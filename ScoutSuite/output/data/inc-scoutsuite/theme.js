const DARK_BOOTSTRAP_THEME = 'inc-bootstrap/css/bootstrap-dark.min.css';
const LIGHT_BOOTSTRAP_THEME = 'inc-bootstrap/css/bootstrap-light.min.css';

const DARK_SCOUT_THEME = 'inc-scoutsuite/css/scoutsuite-dark.css';
const LIGHT_SCOUT_THEME = 'inc-scoutsuite/css/scoutsuite-light.css';

$(document).ready(() => {
  const checkbox = document.getElementById('theme_checkbox')
  if (checkbox) {
    checkbox.checked = isDarkThemeEnabled()
  }
});

// The report sanitizer strips inline on* handlers from rendered templates, so
// the theme switch is bound here (delegated: the menu is rendered later).
$(document).on('change', '#theme_checkbox', toggleTheme);

/**
 * Apply the stored theme. Dark is the default; light only when chosen.
 */
function loadLastTheme() {
  applyTheme(isDarkThemeEnabled())
}

/**
 * Toggles between light and dark themes
 */
function toggleTheme() {
  const darkThemeEnabled = document.getElementById('theme_checkbox').checked
  saveIsDarkThemeEnabled(darkThemeEnabled)
  applyTheme(darkThemeEnabled)
};

/**
 * Sets both stylesheets for the selected theme
 * @param {boolean} dark
 */
function applyTheme(dark) {
  setBootstrapTheme(dark ? DARK_BOOTSTRAP_THEME : LIGHT_BOOTSTRAP_THEME)
  setScoutTheme(dark ? DARK_SCOUT_THEME : LIGHT_SCOUT_THEME)
}

/**
 * Sets the css file location received as the bootstrap theme
 * @param {string} file
 */
function setBootstrapTheme(file) {
  document.getElementById('bootstrap-theme').href = file
}

/**
 * Sets the css file location received as the scout theme
 * @param {string} file
 */
function setScoutTheme(file) {
  document.getElementById('scout-theme').href = file
}

/**
 * Dark unless the viewer explicitly chose light. Storage can be unavailable
 * (private mode, blocked site data); the report then stays dark.
 * @returns {boolean}
 */
function isDarkThemeEnabled() {
  try {
    return localStorage.getItem('dark_theme_enabled') !== 'false'
  } catch (error) {
    return true
  }
}

/**
 * Saves which theme is selected within the localstorage
 * @param {boolean} isDarkThemeEnabled
 */
function saveIsDarkThemeEnabled(isDarkThemeEnabled) {
  try {
    localStorage.setItem('dark_theme_enabled', isDarkThemeEnabled)
  } catch (error) {
    // Preference is a convenience only; the theme still switches for this view.
  }
}
