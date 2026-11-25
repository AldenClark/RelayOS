'use strict';
'require baseclass';
'require rpc';
'require fs';
'require ui';
'require request';

// Follow LuCI's vetted firmware upload and system.validate_firmware_image
// / sysupgrade --test path. Reset uses the native firstboot command.
const validateImage = rpc.declare({
  object: 'system', method: 'validate_firmware_image', params: [ 'path' ],
  expect: { '': { valid: false, allow_backup: false } }
});
const firmwarePath = '/tmp/firmware.bin';
const reboot = rpc.declare({ object: 'system', method: 'reboot', reject: true });

return baseclass.extend({
  handleChangePassword() {
    const current = E('input', { type: 'password', maxlength: 1024, autocomplete: 'current-password' });
    const password = E('input', { type: 'password', maxlength: 128, autocomplete: 'new-password', required: '' });
    const confirmation = E('input', { type: 'password', maxlength: 128, autocomplete: 'new-password', required: '' });
    const error = E('p', { class: 'ar-password-error', role: 'status' });
    const cancel = E('button', { type: 'button', class: 'btn', click: () => ui.hideModal() }, _('Cancel'));
    const submit = E('button', { type: 'submit', class: 'btn cbi-button-action important' }, _('Change password'));
    const controls = [ current, password, confirmation, cancel, submit ];

    const form = E('form', { class: 'ar-password-form', submit: async event => {
      event.preventDefault();
      if (submit.disabled) return;
      if (!password.value || password.value !== confirmation.value) {
        error.textContent = _('The new passwords do not match.');
        return;
      }
      const data = new URLSearchParams({
        token: L.env.token, current_password: current.value, new_password: password.value
      });
      for (const control of controls) control.disabled = true;
      error.textContent = '';
      try {
        const response = await request.post(L.url('admin/relay/password'), data.toString(), {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        const status = response.ok ? response.json().status : null;
        if (status === 'ok') {
          current.value = password.value = confirmation.value = '';
          ui.hideModal();
          ui.addNotification(null, E('p', {}, _('Password changed. Use the new password the next time you sign in.')), 'info');
        }
        else if (status === 'incorrect') {
          current.value = '';
          error.textContent = _('The current password is incorrect.');
        }
        else if (status === 'invalid') {
          error.textContent = _('Enter a valid new password.');
        }
        else {
          error.textContent = _('Unable to change the password.');
        }
      }
      catch (_err) {
        error.textContent = _('Unable to change the password.');
      }
      finally {
        for (const control of controls) control.disabled = false;
      }
    } }, [
      E('label', {}, [ E('span', {}, _('Current password')), current ]),
      E('label', {}, [ E('span', {}, _('New password')), password ]),
      E('label', {}, [ E('span', {}, _('Confirm new password')), confirmation ]),
      error,
      E('div', { class: 'ar-modal-actions' }, [ cancel, submit ])
    ]);
    ui.showModal(_('Change current account password'), form);
    current.focus();
  },

  handleUpload() {
    // Do not gate the file picker on a best-effort filesystem stat or the
    // frontend view permission hint. The upload RPC enforces authorization,
    // and validate_firmware_image + sysupgrade --test enforce compatibility.
    // An unavailable stat must never silently disable the only page action.
    return ui.uploadFile(firmwarePath)
      .then(async image => {
        ui.showModal(_('Checking firmware…'), [ E('p', { class: 'spinning' }, _('Validating compatibility with this device.')) ]);
        const validation = await validateImage(firmwarePath);
        const test = await fs.exec('/sbin/sysupgrade', [ '--test', firmwarePath ]);

        if (validation.valid !== true || test.code !== 0) {
          ui.showModal(_('Firmware not supported'), [
            E('p', { class: 'alert-message danger' }, _('The firmware cannot be safely installed on this device. Choose the matching MD or MF sysupgrade image.')),
            test.stderr ? E('pre', { class: 'ar-upgrade-error' }, test.stderr) : '',
            E('div', { class: 'ar-modal-actions' }, E('button', {
              class: 'btn', click: ui.createHandlerFn(this, 'cancelUpload')
            }, _('Close')))
          ]);
          return;
        }

        const canKeep = Boolean(validation.allow_backup);
        const keep = E('input', { type: 'checkbox', checked: canKeep ? '' : null, disabled: canKeep ? null : '' });
        const confirm = [
          E('p', {}, _('The image passed compatibility checks. Confirm the checksum and start the upgrade. Do not disconnect power during flashing.')),
          E('div', { class: 'ar-upgrade-file' }, [
            E('strong', {}, image.name || _('Selected firmware')),
            E('small', {}, image.size ? `${(image.size / 1024 / 1024).toFixed(1)} MB` : '—'),
            image.sha256sum ? E('code', {}, `SHA256: ${image.sha256sum}`) : ''
          ]),
          E('label', { class: 'ar-upgrade-keep' }, [ keep, _('Keep current settings') ]),
          !canKeep ? E('p', { class: 'ar-muted' }, _('This image cannot preserve existing settings.')) : '',
          E('p', { class: 'ar-muted' }, _('Without preserved settings, the management IP may change because RelayOS obtains its address via DHCP.')),
          E('div', { class: 'ar-modal-actions' }, [
            E('button', { class: 'btn', click: ui.createHandlerFn(this, 'cancelUpload') }, _('Cancel')),
            E('button', {
              class: 'btn cbi-button-action important',
              click: ui.createHandlerFn(this, 'confirmUpgrade', keep)
            }, _('Install firmware'))
          ])
        ];
        ui.showModal(_('Confirm firmware upgrade'), confirm);
      })
      .catch(err => {
        ui.hideModal();
        if (!/cancel|取消/i.test(err.message || '')) {
          // The upload may have completed before the validation RPC failed.
          // Release the firmware-sized tmpfs allocation on that path.
          fs.remove(firmwarePath).catch(() => {});
          ui.addNotification(null, E('p', {}, err.message || _('Firmware upload failed.')));
        }
      });
  },

  cancelUpload() {
    return fs.remove(firmwarePath).finally(ui.hideModal);
  },

  confirmUpgrade(keep) {
    ui.showModal(_('Installing firmware…'), [
      E('p', { class: 'spinning' }, _('Flashing in progress. Do not power off the device. The console will reconnect after reboot.'))
    ]);

    const args = keep.checked ? [ firmwarePath ] : [ '-n', firmwarePath ];
    // The sysupgrade process intentionally ends the web request when rebooting.
    fs.exec('/sbin/sysupgrade', args).then(result => {
      if (result.code !== 0)
        ui.showModal(_('Firmware upgrade command failed.'), [
          E('p', { class: 'alert-message danger' }, result.stderr || _('Firmware upgrade command failed.')),
          E('div', { class: 'ar-modal-actions' }, E('button', {
            class: 'btn', click: ui.createHandlerFn(this, 'cancelUpload')
          }, _('Close')))
        ]);
    }).catch(err => {
      // A successful flash closes the RPC connection. Only a definite access
      // failure proves that sysupgrade was not started.
      if (/access denied|permission denied/i.test(err.message || ''))
        ui.showModal(_('Firmware upgrade command failed.'), [
          E('p', { class: 'alert-message danger' }, err.message)
        ]);
    });
    // A clean upgrade may change the management address (DHCP, not 192.168.1.1).
    ui.awaitReconnect(window.location.host);
  },

  handleReboot() {
    ui.showModal(_('Reboot device?'), [
      E('p', {}, _('The device will briefly go offline. Unsaved changes will be lost.')),
      E('div', { class: 'ar-modal-actions' }, [
        E('button', { class: 'btn', click: ui.hideModal }, _('Cancel')),
        E('button', {
          class: 'btn cbi-button-action important',
          click: ui.createHandlerFn(this, 'confirmReboot')
        }, _('Reboot device'))
      ])
    ]);
  },

  async confirmReboot() {
    ui.showModal(_('Rebooting device…'), [
      E('p', { class: 'spinning' }, _('Waiting for the device to reconnect.'))
    ]);
    try {
      await reboot();
    }
    catch (err) {
      ui.showModal(_('Device reboot failed.'), [
        E('p', { class: 'alert-message danger' }, err.message || _('Device reboot failed.')),
        E('div', { class: 'ar-modal-actions' }, E('button', { class: 'btn', click: ui.hideModal }, _('Close')))
      ]);
      return;
    }
    ui.awaitReconnect(window.location.host);
  },

  handleFactoryReset() {
    ui.showModal(_('Reset system?'), [
      E('p', {}, _('All settings will be erased and the device will restart. Its management address will be obtained via DHCP.')),
      E('div', { class: 'ar-modal-actions' }, [
        E('button', { class: 'btn', click: ui.hideModal }, _('Cancel')),
        E('button', {
          class: 'btn cbi-button-negative',
          click: ui.createHandlerFn(this, 'confirmFactoryReset')
        }, _('Reset system'))
      ])
    ]);
  },

  async confirmFactoryReset() {
    ui.showModal(_('Resetting system…'), [
      E('p', { class: 'spinning' }, _('Erasing settings and restarting. Find the new address in your router’s DHCP leases.'))
    ]);
    const failed = message => ui.showModal(_('System reset failed.'), [
      E('p', { class: 'alert-message danger' }, message),
      E('div', { class: 'ar-modal-actions' }, E('button', { class: 'btn', click: ui.hideModal }, _('Close')))
    ]);
    try {
      const result = await fs.exec('/sbin/firstboot', [ '-r', '-y' ]);
      if (result.code !== 0) {
        failed(result.stderr || _('System reset failed.'));
        return;
      }
    }
    catch (err) {
      // Reboot can terminate the request. A definite RPC rejection is a
      // failure; a lost transport leaves the restart dialog and reconnects.
      if (err.name === 'RPCError' || /access denied|permission denied/i.test(err.message || '')) {
        failed(err.message);
        return;
      }
    }
    ui.awaitReconnect(window.location.host);
  },

  render() {
    return E('section', { class: 'ar-system-section' }, [
      E('h2', {}, _('System management')),
      E('div', { class: 'ar-panel ar-system-actions' }, [
        E('div', { class: 'ar-system-action' }, [
          E('strong', {}, _('Change current account password')),
          E('button', {
            class: 'btn cbi-button-action',
            disabled: L.hasViewPermission() ? null : true,
            click: ui.createHandlerFn(this, 'handleChangePassword')
          }, _('Change password…'))
        ]),
        E('div', { class: 'ar-system-action' }, [
          E('strong', {}, _('Firmware upgrade')),
          E('button', {
            class: 'btn cbi-button-action important',
            click: ui.createHandlerFn(this, 'handleUpload')
          }, _('Choose firmware…'))
        ]),
        E('div', { class: 'ar-system-action' }, [
          E('strong', {}, _('Reboot device')),
          E('button', {
            class: 'btn cbi-button-action',
            disabled: L.hasViewPermission() ? null : true,
            click: ui.createHandlerFn(this, 'handleReboot')
          }, _('Reboot device…'))
        ]),
        E('div', { class: 'ar-system-action' }, [
          E('strong', {}, _('Reset system')),
          E('button', {
            class: 'btn cbi-button-negative',
            disabled: L.hasViewPermission() ? null : true,
            click: ui.createHandlerFn(this, 'handleFactoryReset')
          }, _('Reset system…'))
        ])
      ])
    ]);
  }
});
