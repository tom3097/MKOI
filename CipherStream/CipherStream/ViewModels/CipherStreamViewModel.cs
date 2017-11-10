using CipherStream.Models;
using CipherStream.Navigation;
using System.Windows.Input;
using System.Windows.Navigation;

namespace CipherStream.ViewModels
{
    /// <summary>
    /// CipherStreamViewModel class.
    /// This class provides logic for the application.
    /// </summary>
    public class CipherStreamViewModel
    {
        #region properties

        /// <summary>
        /// An instance of NavigationPage class.
        /// </summary>
        public PageNavigation NavigationPage { get; set; }

        /// <summary>
        /// Command used to navigate to another page.
        /// </summary>
        public ICommand NavigateToCommand { get; private set; }

        /// <summary>
        /// Command used to navigate back from the current page.
        /// </summary>
        public ICommand NavigateBackCommand { get; private set; }

        #endregion

        #region methods

        /// <summary>
        /// CipherStreamViewModel class constructor.
        /// Initializes NavigateToCommand and NavigateBackCommand.
        /// </summary>
        /// <param name="navigation">An instance of NavigationService class.</param>
        public CipherStreamViewModel(NavigationService navigation)
        {
            NavigationPage = new PageNavigation(navigation);

            NavigateToCommand = new RelayCommand(
                obj => NavigationPage.NavigateToCommand.Execute(obj),
                obj => NavigationPage.NavigateToCommand.CanExecute(obj));

            NavigateBackCommand = new RelayCommand(
                obj => NavigationPage.NavigateBackCommand.Execute(obj),
                obj => NavigationPage.NavigateBackCommand.CanExecute(obj));
        }
        
        #endregion
    }
}
