using CipherStream.Models;
using System;
using System.Windows.Input;
using System.Windows.Navigation;

namespace CipherStream.Navigation
{
    /// <summary>
    /// PageNavigation class.
    /// This class is used to navigate between the pages.
    /// </summary>
    public class PageNavigation
    {
        #region properties

        /// <summary>
        /// Command used to navigate to another page.
        /// </summary>
        public ICommand NavigateToCommand { get; private set; }

        /// <summary>
        /// Command used to navigate back from the current page.
        /// </summary>
        public ICommand NavigateBackCommand { get; set; }

        #endregion

        #region methods

        /// <summary>
        /// PageNavigation class constructor.
        /// Initializes NavigateToCommand and NavigateBackCommand.
        /// </summary>
        /// <param name="navigation">An instance of NavigationService class.</param>
        public PageNavigation(NavigationService navigation)
        {
            NavigateToCommand = new RelayCommand((object obj) =>
            {
                var page = Activator.CreateInstance(obj as Type);
                navigation.Navigate(page);
            },
            (object obj) =>
            {
                return true;
            });

            NavigateBackCommand = new RelayCommand((object obj) =>
            {
                navigation.GoBack();
            },
            (object obj) =>
            {
                return navigation.CanGoBack;
            });
        }

        #endregion
    }
}
