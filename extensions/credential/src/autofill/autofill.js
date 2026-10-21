// Generic DOM filling.
//
// Only the mechanics live here: find the field, set the value, fire the
// events a page expects. Site specific quirks belong in the fill script
// packages, not in this file.

export function setNativeValue(element, value) {
  const proto =
    element instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value');
  if (setter && setter.set) setter.set.call(element, value);
  else element.value = value;
}

export function fireInputEvents(element) {
  for (const type of ['input', 'change']) {
    element.dispatchEvent(new Event(type, { bubbles: true }));
  }
}

export function fillField(element, value) {
  if (!element) return false;
  setNativeValue(element, value);
  fireInputEvents(element);
  return true;
}
