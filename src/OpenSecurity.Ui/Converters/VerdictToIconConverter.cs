using System.Globalization;
using System.Windows.Data;
using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Ui.Converters;

/// <summary>Maps a Verdict to a Segoe MDL2 Assets glyph for the badge icon.</summary>
public sealed class VerdictToIconConverter : IValueConverter
{
    private const string CheckMark = "\uE73E";
    private const string Warning = "\uE7BA";
    private const string Cancel = "\uE711";
    private const string Info = "\uE946";

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        Verdict.Clean => CheckMark,
        Verdict.Suspicious => Warning,
        Verdict.Malicious => Cancel,
        Verdict.Error => Info,
        _ => Info
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
