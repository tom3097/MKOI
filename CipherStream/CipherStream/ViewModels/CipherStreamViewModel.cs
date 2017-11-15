using CipherStream.Models;
using CipherStream.Navigation;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Linq;
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

        /// <summary>
        /// Output produced by Bouncy Castle library function.
        /// </summary>
        private string _bouncyCastleOutput;

        /// <summary>
        /// Output produced by custom implementation.
        /// </summary>
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

        /// <summary>
        /// Command used to process bytes using RC4 algorithm.
        /// </summary>
        public ICommand ProcessRC4Command { get; private set; }

        /// <summary>
        /// Command used to process bytes using ChaCha20 algorithm.
        /// </summary>
        public ICommand ProcessChaCha20Command { get; private set; }

        /// <summary>
        /// Bouncy castle output property.
        /// </summary>
        public string BouncyCastleOutput
        {
            get => _bouncyCastleOutput;
            set => SetProperty(ref _bouncyCastleOutput, value);
        }

        /// <summary>
        /// Custom output property.
        /// </summary>
        public string CustomOutput
        {
            get => _customOutput;
            set => SetProperty(ref _customOutput, value);
        }

        /// <summary>
        /// Key used for encoding / decoding tasks.
        /// </summary>
        public string CipherKey { get; set; }

        /// <summary>
        /// Message which is to be encoded / decoded.
        /// </summary>
        public string CipherMessage { get; set; }

        /// <summary>
        /// Nonce used in ChaCha20 algorithm.
        /// </summary>
        public string CipherNonce { get; set; }

        /// <summary>
        /// Indicates whether custom output should be printed as string or hexadecimal values.
        /// </summary>
        public bool CustomOutputAsHex { get; set; }

        /// <summary>
        /// Indicates whether bouncy castle output should be printed as string or hexadecimal values.
        /// </summary>
        public bool BouncyCastleOutputAsHex { get; set; }

        /// <summary>
        /// Indicates whether input message is provided as string or hexadecimal values.
        /// </summary>
        public bool TextAsHex { get; set; }

        /// <summary>
        /// Indicates whether input key is provided as string or hexadecimal values.
        /// </summary>
        public bool KeyAsHex { get; set; }

        /// <summary>
        /// Indicates whether input nonce is provided as string or hexadecimal values.
        /// </summary>
        public bool NonceAsHex { get; set; }

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
                obj => NavigateTo(obj),
                obj => NavigationPage.NavigateToCommand.CanExecute(obj));

            NavigateBackCommand = new RelayCommand(
                obj => NavigateBack(obj),
                obj => NavigationPage.NavigateBackCommand.CanExecute(obj));

            ProcessRC4Command = new RelayCommand(
                obj => ProcessRC4(obj),
                obj => true);

            ProcessChaCha20Command = new RelayCommand(
                obj => ProcessChaCha20(obj),
                obj => true);
        }

        /// <summary>
        /// Resets appropriate variables, goes to the initial state.
        /// </summary>
        private void Reset()
        {
            CustomOutputAsHex = true;
            BouncyCastleOutputAsHex = true;
            KeyAsHex = false;
            TextAsHex = false;
            NonceAsHex = false;

            BouncyCastleOutput = null;
            CustomOutput = null;
            CipherNonce = null;
            CipherMessage = null;
            CipherKey = null;
        }

        /// <summary>
        /// Goes to the initial state and navigates to proper page.
        /// </summary>
        /// <param name="obj">New page's type.</param>
        private void NavigateTo(object obj)
        {
            Reset();
            NavigationPage.NavigateToCommand.Execute(obj);
        }

        /// <summary>
        /// Goes to the initial state and navigates back from current page.
        /// </summary>
        /// <param name="obj">Unused.</param>
        private void NavigateBack(object obj)
        {
            Reset();
            NavigationPage.NavigateBackCommand.Execute(obj);
        }

        /// <summary>
        /// Performs encoding and decoing taks using RC4 algorithm.
        /// </summary>
        /// <param name="obj">Unused.</param>
        private void ProcessRC4(object obj)
        {
            byte[] keyByte = KeyAsHex ? CipherKey.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherKey);
            byte[] textByte = TextAsHex ? CipherMessage.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherMessage);

            if (keyByte.Length == 0 || textByte.Length == 0)
            {
                return;
            }

            // custom implementation
            try
            {
                var rc4Engine = new RC4CipherEngine();
                rc4Engine.Init(keyByte);
                var customOutput = rc4Engine.ProcessBytes(textByte);

                CustomOutput = CustomOutputAsHex ? BitConverter.ToString(customOutput)
                    : Encoding.UTF8.GetString(customOutput);
            }
            catch
            {
                return;
            }

            //Bouncy castle implementation
            try
            {
                var rc4Bouncy = new RC4Engine();
                rc4Bouncy.Init(true, new KeyParameter(keyByte));
                byte[] bouncyCastleOutput = new byte[textByte.Length];
                rc4Bouncy.ProcessBytes(textByte, 0, textByte.Length, bouncyCastleOutput, 0);

                BouncyCastleOutput = BouncyCastleOutputAsHex ? BitConverter.ToString(bouncyCastleOutput)
                    : Encoding.UTF8.GetString(bouncyCastleOutput);
            }
            catch
            {
                return;
            }
        }

        /// <summary>
        /// Performs encoding and decoing taks using ChaCha20 algorithm.
        /// </summary>
        /// <param name="obj">Unused.</param>
        private void ProcessChaCha20(object obj)
        {
            byte[] keyByte = KeyAsHex ? CipherKey.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherKey);
            byte[] textByte = TextAsHex ? CipherMessage.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherMessage);
            byte[] nonceByte = NonceAsHex ? CipherNonce.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherNonce);

            if (keyByte == null || textByte == null || nonceByte == null)
            {
                return;
            }

            // custom implementation
            try
            {
                var chacha20Engine = new ChaCha20CipherEngine();
                chacha20Engine.Init(keyByte);
                byte[] customOutput = chacha20Engine.ProcessBytes(textByte, nonceByte);

                CustomOutput = CustomOutputAsHex ? BitConverter.ToString(customOutput)
                    : Encoding.UTF8.GetString(customOutput);
            }
            catch
            {
                return;
            }

            // Bouncy castle implementation
            try
            {
                var chacha20Bouncy = new ChaChaEngine();
                chacha20Bouncy.Init(true, new KeyParameter(keyByte));
                byte[] bouncyCastleOutput = new byte[textByte.Length];
                chacha20Bouncy.ProcessBytes(textByte, 0, textByte.Length, bouncyCastleOutput, 0);

                BouncyCastleOutput = BouncyCastleOutputAsHex ? BitConverter.ToString(bouncyCastleOutput)
                    : Encoding.UTF8.GetString(bouncyCastleOutput);
            }
            catch
            {
                return;
            }
        }

        #endregion
    }
}