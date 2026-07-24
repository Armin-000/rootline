(() => {
  const THEME_STORAGE_KEY = "rootline-theme-v3";
  const DEFAULT_THEME = "light";
  const DARK_THEME = "dark";

  try {
    const storedTheme = localStorage.getItem(THEME_STORAGE_KEY);
    const theme = storedTheme === DARK_THEME ? DARK_THEME : DEFAULT_THEME;

    document.documentElement.dataset.theme = theme;

    const themeColor = document.querySelector('meta[name="theme-color"]');
    if (themeColor) {
      themeColor.content = theme === DARK_THEME ? "#171a18" : "#f6f7f4";
    }
  } catch {
    document.documentElement.dataset.theme = DEFAULT_THEME;
  }
})();
