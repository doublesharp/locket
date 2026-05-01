// Unit tests for the tray menu action mapping module.
//
// Mirrors the pure helpers exercised on the Rust side under
// `crates/locket-app/src-tauri/src/tray.rs`. Keeps the wire contract
// pinned even when the webview is the only consumer.

import { describe, expect, it } from 'vitest';

import {
  TRAY_MENU_ACTIONS,
  trayActionSideEffect,
  trayActionToView,
  type TrayMenuAction,
} from './menuActions';

describe('trayActionToView', () => {
  it('routes each action to the spec-defined view', () => {
    const cases: Array<[TrayMenuAction, ReturnType<typeof trayActionToView>]> = [
      ['open-app', 'dashboard'],
      ['lock-vault', null],
      ['unlock-vault', 'dashboard'],
      ['switch-profile', 'dashboard'],
      ['run-policy', 'policies'],
      ['start-scan', 'scan'],
    ];
    for (const [action, expected] of cases) {
      expect(trayActionToView(action)).toBe(expected);
    }
  });

  it('treats lock-vault as the only headless action', () => {
    for (const action of TRAY_MENU_ACTIONS) {
      const view = trayActionToView(action);
      if (action === 'lock-vault') {
        expect(view).toBeNull();
      } else {
        expect(view).not.toBeNull();
      }
    }
  });
});

describe('trayActionSideEffect', () => {
  it('maps every action to a side effect', () => {
    const cases: Array<[TrayMenuAction, ReturnType<typeof trayActionSideEffect>]> = [
      ['open-app', 'none'],
      ['lock-vault', 'lock-vault'],
      ['unlock-vault', 'open-unlock-modal'],
      ['switch-profile', 'open-profile-switcher'],
      ['run-policy', 'refresh-policies'],
      ['start-scan', 'start-scan'],
    ];
    for (const [action, expected] of cases) {
      expect(trayActionSideEffect(action)).toBe(expected);
    }
  });
});
