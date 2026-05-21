// Polyfill IndexedDB for the Node-based test runner. `crypto.subtle` is
// already provided natively by Node 20+, so nothing else is needed.
import 'fake-indexeddb/auto';
