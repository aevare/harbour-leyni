# After some use

## Note
* ~~Allow copy of notes~~ done: copy button next to Show notes
* ~~If there is no details, then dont show details button.~~ done: hasNotes/hasDetails
  flags; sections hidden when empty. The show-button stays by design: details can
  contain card numbers/hidden fields, decrypted only on demand.

## Search
* ~~Keyboard closes when the list refilters~~ done: list items took focus on
  refilter; SilicaListView now has `currentIndex: -1`. Debounce removed.

## List
* ~~Favourites list missing~~ done: favourites sort first with section headers
* What to do about groups/folders? — deferred until after daily-use period;
  revisit collections/organizations UI then

