using Microsoft.UI.Xaml;
using uniffi.lazymail_core;

namespace LazyMail;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Version.Text = LazymailCoreMethods.CoreVersion();
    }
}
