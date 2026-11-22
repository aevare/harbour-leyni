.pragma library

// Colours/icons shared by Toast and InlineBanner. A .pragma library has no
// imports and can't read Theme enums, so callers pass the Theme object in
// plus lightOnDark as a bool.

function tone(theme, variant, lightOnDark) {
    switch (variant) {
    case "error":
        return theme.errorColor
    case "warning":
        // Silica has no warning colour; amber, darkened on light ambiences.
        return lightOnDark ? "#ffc46b" : "#8a5a00"
    case "success":
    case "undo":
        return theme.highlightColor
    default:
        return theme.primaryColor
    }
}

function actionColor(theme, variant) {
    return variant === "error" ? theme.errorColor : theme.highlightColor
}

function icon(variant) {
    switch (variant) {
    case "success": return "success"
    case "error": return "error"
    case "warning": return "error"
    case "undo": return "delete"
    default: return "info"
    }
}
