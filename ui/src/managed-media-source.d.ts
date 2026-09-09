// TypeScript 5.7's DOM lib has no ManagedMediaSource, but iPhone Safari (iOS
// 17.1+) exposes ONLY that constructor -- window.MediaSource is undefined
// there -- so views/Watch.tsx has to feature-detect it to play a camera on a
// phone at all. Delete this file once the DOM lib ships the type.
//
// Minimal surface on purpose: ManagedMediaSource extends MediaSource, so
// addSourceBuffer / readyState / the sourceopen event all come from the
// built-in type, and the two advisory streaming events go through
// EventTarget's (type: string, ...) overload with no event-map declaration.

export {};

declare global {
  interface ManagedMediaSource extends MediaSource {
    /**
     * UA buffering hint: false means "stop feeding me for now". Advisory only
     * -- appends are still legal -- see the startstreaming/endstreaming
     * handling in Watch.tsx.
     */
    readonly streaming: boolean;
  }

  interface ManagedMediaSourceConstructor {
    prototype: ManagedMediaSource;
    new (): ManagedMediaSource;
    isTypeSupported(type: string): boolean;
  }

  // Declared possibly-undefined so every call site is forced to feature-detect.
  // Do NOT also redeclare window.MediaSource as optional: that collides with
  // the DOM lib. Use a `typeof window.MediaSource` guard instead.
  var ManagedMediaSource: ManagedMediaSourceConstructor | undefined;
}
