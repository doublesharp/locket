// Pure mapping module for the tray menu action contract.
//
// The Rust side (`crates/locket-app/src-tauri/src/tray.rs`) emits a
// `tray-menu-action` event with one of the kebab-case strings below.
// The webview maps that wire string to:
//
//   - the primary view to focus, and
//   - whether the action triggers a side-effect handler in `App.vue`.
//
// Keeping this logic in a vscode-free module lets us unit test the
// mapping contract without spinning up the Vue runtime or a Tauri
// webview.

export type TrayMenuAction =
  | 'open-app'
  | 'lock-vault'
  | 'unlock-vault'
  | 'switch-profile'
  | 'run-policy'
  | 'start-scan';

export type TrayView =
  | 'dashboard'
  | 'secrets'
  | 'versions'
  | 'execution'
  | 'devices'
  | 'audit'
  | 'scan'
  | 'policies'
  | 'recovery'
  | 'settings';

/** Side-effect categories that the App-level handler invokes. */
export type TraySideEffect =
  | 'none'
  | 'lock-vault'
  | 'open-unlock-modal'
  | 'open-profile-switcher'
  | 'refresh-policies'
  | 'start-scan';

/**
 * Pure mapping from a tray action wire string to the primary view the
 * desktop should focus before any side-effect runs.
 */
export function trayActionToView(action: TrayMenuAction): TrayView | null {
  switch (action) {
    case 'open-app':
      return 'dashboard';
    case 'lock-vault':
      return null;
    case 'unlock-vault':
      return 'dashboard';
    case 'switch-profile':
      return 'dashboard';
    case 'run-policy':
      return 'policies';
    case 'start-scan':
      return 'scan';
    default:
      return null;
  }
}

/**
 * Pure mapping from a tray action wire string to the side-effect class
 * the App-level handler should run after focusing the view.
 */
export function trayActionSideEffect(action: TrayMenuAction): TraySideEffect {
  switch (action) {
    case 'open-app':
      return 'none';
    case 'lock-vault':
      return 'lock-vault';
    case 'unlock-vault':
      return 'open-unlock-modal';
    case 'switch-profile':
      return 'open-profile-switcher';
    case 'run-policy':
      return 'refresh-policies';
    case 'start-scan':
      return 'start-scan';
    default:
      return 'none';
  }
}

/** All tray menu actions in spec order. */
export const TRAY_MENU_ACTIONS: readonly TrayMenuAction[] = [
  'open-app',
  'lock-vault',
  'unlock-vault',
  'switch-profile',
  'run-policy',
  'start-scan',
];
