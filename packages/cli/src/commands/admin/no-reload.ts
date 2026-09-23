// The one description of `--no-reload`, shared by every policy-mutating admin
// command. The flag saves the desired change without activating a new
// effective policy generation; the change applies at the next runtime start
// or `runfree runtime reload-policy`. Reload and converge are different
// operations in this code, and the descriptions used to name each of them.

export const NO_RELOAD_DESCRIBE = "Save the change without activating it; it applies at the next runtime start or reload-policy";
