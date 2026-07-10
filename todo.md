# After some use

## Note
* ~~Allow copy of notes~~ done: copy button next to Show notes
* ~~If there is no details, then dont show details button.~~ done: hasNotes/hasDetails
  flags; sections hidden when empty. The show-button stays by design: details can
  contain card numbers/hidden fields, decrypted only on demand.

## Search
* Keyboard closes when the list refilters — root cause still open. Ruled out:
  focusOutBehavior (KeepFocus set), per-keystroke model reset (model now emits
  row-level diffs, verified by test). Mitigated with a 400 ms debounce so it
  can no longer happen mid-word; Enter/clear apply immediately. To pin it down:
  capture journalctl while typing on device.

## List
* ~~Favourites list missing~~ done: favourites sort first with section headers
* What to do about groups/folders? — deferred until after daily-use period;
  revisit collections/organizations UI then

