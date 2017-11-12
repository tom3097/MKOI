using CipherStream.Models;
using CipherStream.Navigation;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Text;
using System.Windows.Input;
using System.Windows.Navigation;

namespace CipherStream.ViewModels
{
    /// <summary>
    /// CipherStreamViewModel class.
    /// This class provides logic for the application.
    /// </summary>
    public class CipherStreamViewModel : ViewModelBase
    {
        #region fields

        private string _bouncyCastleOutput;

        private string _customOutput;

        #endregion

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

        public ICommand ProcessRC4Command { get; private set; }

        public ICommand ProcessChaCha20Command { get; private set; }

        public string BouncyCastleOutput
        {
            get => _bouncyCastleOutput;
            set => SetProperty(ref _bouncyCastleOutput, value);
        }

        public string CustomOutput
        {
            get => _customOutput;
            set => SetProperty(ref _customOutput, value);
        }

        public string CipherKey { get; set; }

        public string CipherMessage { get; set; }

        public ICommand ClearCommand { get; private set; }

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

            ProcessRC4Command = new RelayCommand(
                obj => ProcessRC4(obj),
                obj => true);

            ProcessChaCha20Command = new RelayCommand(
                obj => ProcessChaCha20(obj),
                obj => true);

            ClearCommand = new RelayCommand(obj => Clear(obj), obj => true);
        }

        private void Clear(object obj)
        {
            CustomOutput = null;
            BouncyCastleOutput = null;
        }

        private void ProcessRC4(object obj)
        {
            // generalnie pomysl jest taki zeby dla danej pary (klucz, wiadomosc)
            // zaszyfrowac ja dwoma implementacjami, obie wypisac i pokazac ze jest tak samo

            var keyByte = Encoding.UTF8.GetBytes(CipherKey);
            var textByte = Encoding.UTF8.GetBytes(CipherMessage);

            var rc4Engine = new RC4CipherEngine();
            rc4Engine.Init(keyByte);
            var customOutput = rc4Engine.ProcessBytes(textByte);
            CustomOutput = BitConverter.ToString(customOutput);

            var rc4Bouncy = new RC4Engine();
            rc4Bouncy.Init(true, new KeyParameter(keyByte));
            byte[] bouncyCastleOutput = new byte[textByte.Length];
            rc4Bouncy.ProcessBytes(textByte, 0, textByte.Length, bouncyCastleOutput, 0);
            BouncyCastleOutput = BitConverter.ToString(bouncyCastleOutput);
        }

        private void ProcessChaCha20(object obj)
        {
            var keyByte = Encoding.UTF8.GetBytes(CipherKey);
            var textByte = Encoding.UTF8.GetBytes(CipherMessage);
        }
        
        #endregion
    }
}
