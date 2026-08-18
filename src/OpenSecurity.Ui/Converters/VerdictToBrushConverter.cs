using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Ui.Converters;

public sealed class VerdictToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var brushKey = value switch
        {
            Verdict.Clean => "CleanBrush",
            Verdict.Suspicious => "SuspiciousBrush",
            Verdict.Malicious => "MaliciousBrush",
            Verdict.Error => "ErrorBrush",
            _ => "TextSecondaryBrush"
        };

        return System.Windows.Application.Current.TryFindResource(brushKey) as Brush
               ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
