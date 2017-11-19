using CipherStream.ViewModels;
using CipherStream.Views;
using System.Windows;

namespace CipherStream
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        #region properties

        /// <summary>
        /// An instance of CipherStreamViewModel class.
        /// </summary>
        public CipherStreamViewModel AppCipherStreamViewModel { get; private set; }

        #endregion

        #region methods

        /// <summary>
        /// Invoked on start up.
        /// </summary>
        /// <param name="e">Start up event arguments.</param>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            MainWindow mainWindow = new MainWindow();
            mainWindow.Show();

            AppCipherStreamViewModel = new CipherStreamViewModel(mainWindow.MainFrame.NavigationService);

            MainPage mainPage = new MainPage();
            mainWindow.MainFrame.Navigate(mainPage);
        }

        #endregion
    }
}
