// INERT TEST FIXTURE — Trojan Source style bidirectional-override injection.
//
// The line below contains a literal U+202E (RIGHT-TO-LEFT OVERRIDE) inside the
// comment. A reviewer's editor renders the remainder in reverse order, so what
// reads as an inert comment can hide a live statement. The character is
// invisible here by design; that is the entire point of the technique.

function isAdmin(user) {
  /* check permissions ‮ } ehcac morf nruter */
  return user.role === "admin";
}

module.exports = { isAdmin };
