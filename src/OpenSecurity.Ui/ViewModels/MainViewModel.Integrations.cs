using OpenSecurity.Core.Settings;
using OpenSecurity.Ui.Services;

namespace OpenSecurity.Ui.ViewModels;

/// <summary>OS-level integration toggles: launching with Windows and the Explorer right-click menu.</summary>
public sealed partial class MainViewModel
{
    private readonly string _settingsFilePath;
    private readonly AppSettings _settings;
    private readonly Action<bool>? _applyAutoStart;
    private bool _startWithWindows;
    private bool _isContextMenuEnabled;

    public bool StartWithWindows
    {
        get => _startWithWindows;
        set
        {
            _startWithWindows = value;
            _settings.StartWithWindows = value;
            _settings.Save(_settingsFilePath);
            _applyAutoStart?.Invoke(value);
            OnPropertyChanged();
        }
    }

    public bool IsContextMenuEnabled
    {
        get => _isContextMenuEnabled;
        set
        {
            if (value)
                ContextMenuManager.Register();
            else
                ContextMenuManager.Unregister();

            _isContextMenuEnabled = value;
            OnPropertyChanged();
        }
    }

    private void InitializeIntegrations()
    {
        _startWithWindows = _settings.StartWithWindows;
        _isContextMenuEnabled = ContextMenuManager.IsRegistered();

        // Re-apply on every launch rather than only when the checkbox is toggled, so the Run
        // key registration self-heals if it was ever cleared externally (a Windows update, a
        // cleanup tool, a manual edit) without silently leaving the saved setting and actual
        // registration out of sync.
        if (_startWithWindows)
            _applyAutoStart?.Invoke(true);
    }
}
