using CipherStream.Models;
using CipherStream.Navigation;
using Microsoft.Win32;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
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

        /// <summary>
        /// File which content is to be encrypted / decrypted.
        /// </summary>
        private string _inputFile;

        /// <summary>
        /// Describes the error, if occured.
        /// </summary>
        private string _errorMsg;

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
        /// Command used to process bytes from GUI using RC4 algorithm.
        /// </summary>
        public ICommand ProcessRC4GUICommand { get; private set; }

        /// <summary>
        /// Command used to process bytes from file using RC4 algorithm.
        /// </summary>
        public ICommand ProcessRC4FileCommand { get; private set; }

        /// <summary>
        /// Command used to process bytes from GUI using ChaCha20 algorithm.
        /// </summary>
        public ICommand ProcessChaCha20GUICommand { get; private set; }

        /// <summary>
        /// Command used to process bytes from file using ChaCha20 algorithm.
        /// </summary>
        public ICommand ProcessChaCha20FileCommand { get; private set; }

        /// <summary>
        /// Command used for file selection.
        /// </summary>
        public ICommand FileSelectCommand { get; private set; }

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
        /// Input file property.
        /// </summary>
        public string InputFile
        {
            get => _inputFile;
            set => SetProperty(ref _inputFile, value);
        }

        /// <summary>
        /// Output file property.
        /// </summary>
        public string OutputFile { get; set; }

        /// <summary>
        /// Key used for encryption / decryption tasks.
        /// </summary>
        public string CipherKey { get; set; }

        /// <summary>
        /// Message which is to be encrypted / decrypted.
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

        /// <summary>
        /// Indicates whether input file contains plain text or hexadecimal values.
        /// </summary>
        public bool InputFileAsHex { get; set; }

        /// <summary>
        /// Indicated whether output file should contain plain text or hexadecimal values.
        /// </summary>
        public bool OutputFileAsHex { get; set; }

        /// <summary>
        /// Error message property.
        /// </summary>
        public string ErrorMsg
        {
            get => _errorMsg;
            set => SetProperty(ref _errorMsg, value);
        }

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

            ProcessRC4GUICommand = new RelayCommand(
                obj => ProcessRC4GUI(obj),
                obj => true);

            ProcessChaCha20GUICommand = new RelayCommand(
                obj => ProcessChaCha20GUI(obj),
                obj => true);

            FileSelectCommand = new RelayCommand(
                obj => FileSelect(obj),
                obj => true);

            ProcessRC4FileCommand = new RelayCommand(
                obj => ProcessRC4File(obj),
                obj => true);

            ProcessChaCha20FileCommand = new RelayCommand(
                obj => ProcessChaCha20File(obj),
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
            InputFileAsHex = false;
            OutputFileAsHex = true;

            BouncyCastleOutput = null;
            CustomOutput = null;
            CipherNonce = null;
            CipherMessage = null;
            CipherKey = null;
            ErrorMsg = null;
            InputFile = null;
            OutputFile = null;
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
        private void ProcessRC4GUI(object obj)
        {
            ErrorMsg = null;

            byte[] keyByte = KeyAsHex ? CipherKey.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherKey);
            byte[] textByte = TextAsHex ? CipherMessage.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherMessage);

            // custom implementation
            try
            {
                var rc4Engine = new RC4CipherEngine();
                rc4Engine.Init(keyByte);
                var customOutput = rc4Engine.ProcessBytes(textByte);

                CustomOutput = CustomOutputAsHex ? BitConverter.ToString(customOutput)
                    : Encoding.UTF8.GetString(customOutput);
            }
            catch (Exception e)
            {
                ErrorMsg = "Processing bytes using custom RC4 failed: " + e.Message;
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
            catch (Exception e)
            {
                ErrorMsg = "Processing bytes using Bouncy Castle RC4 failed: " + e.Message;
                return;
            }
        }

        /// <summary>
        /// Performs encoding and decoing taks using ChaCha20 algorithm.
        /// </summary>
        /// <param name="obj"></param>
        private void ProcessChaCha20GUI(object obj)
        {
            ErrorMsg = null;

            byte[] keyByte = KeyAsHex ? CipherKey.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherKey);
            byte[] textByte = TextAsHex ? CipherMessage.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherMessage);
            byte[] nonceByte = NonceAsHex ? CipherNonce.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherNonce);

            // custom implementation
            try
            {
                var chacha20Engine = new ChaCha20CipherEngine();
                chacha20Engine.Init(keyByte);
                byte[] customOutput = chacha20Engine.ProcessBytes(textByte, nonceByte);

                CustomOutput = CustomOutputAsHex ? BitConverter.ToString(customOutput)
                    : Encoding.UTF8.GetString(customOutput);
            }
            catch (Exception e)
            {
                ErrorMsg = "Processing bytes using custom ChaCha20 failed: " + e.Message;
                return;
            }

            // Bouncy castle implementation
            try
            {
                var chacha20Bouncy = new ChaChaEngine();
                chacha20Bouncy.Init(true, new ParametersWithIV(new KeyParameter(keyByte), nonceByte));
                byte[] bouncyCastleOutput = new byte[textByte.Length];
                chacha20Bouncy.ProcessBytes(textByte, 0, textByte.Length, bouncyCastleOutput, 0);

                BouncyCastleOutput = BouncyCastleOutputAsHex ? BitConverter.ToString(bouncyCastleOutput)
                    : Encoding.UTF8.GetString(bouncyCastleOutput);
            }
            catch (Exception e)
            {
                ErrorMsg = "Processing bytes using Bouncy Castle ChaCha20 failed: " + e.Message;
                return;
            }
        }

        /// <summary>
        /// Shows UI for file selection.
        /// </summary>
        /// <param name="obj">Unused.</param>
        private void FileSelect(object obj)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
            if (openFileDialog.ShowDialog() == true)
                InputFile = openFileDialog.FileName;
        }

        /// <summary>
        /// Performs encoding and decoing taks using RC4 algorithm.
        /// </summary>
        /// <param name="obj">Unused.</param>
        private void ProcessRC4File(object obj)
        {
            ErrorMsg = null;

            byte[] keyByte = KeyAsHex ? CipherKey.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherKey);
            byte[] textByte;

            try
            {
                textByte = InputFileAsHex ? File.ReadAllText(InputFile).Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                    : Encoding.UTF8.GetBytes(File.ReadAllText(InputFile));
            }
            catch
            {
                ErrorMsg = "Selected file is corrupted or missing.";
                return;
            }

            // custom implementation
            try
            {
                var rc4Engine = new RC4CipherEngine();
                rc4Engine.Init(keyByte);
                var customOutput = rc4Engine.ProcessBytes(textByte);

                string toSave = OutputFileAsHex ? BitConverter.ToString(customOutput)
                    : Encoding.UTF8.GetString(customOutput);

                var dir = Path.GetDirectoryName(OutputFile);
                var name = Path.GetFileName(OutputFile);

                File.WriteAllText(String.Format("{0}{1}Custom_{2}", dir, Path.DirectorySeparatorChar, name), toSave);
            }
            catch (Exception e)
            {
                ErrorMsg = "Processing bytes using custom RC4 failed: " + e.Message;
                return;
            }

            //Bouncy castle implementation
            try
            {
                var rc4Bouncy = new RC4Engine();
                rc4Bouncy.Init(true, new KeyParameter(keyByte));
                byte[] bouncyCastleOutput = new byte[textByte.Length];
                rc4Bouncy.ProcessBytes(textByte, 0, textByte.Length, bouncyCastleOutput, 0);

                string toSave = OutputFileAsHex ? BitConverter.ToString(bouncyCastleOutput)
                    : Encoding.UTF8.GetString(bouncyCastleOutput);

                var dir = Path.GetDirectoryName(OutputFile);
                var name = Path.GetFileName(OutputFile);

                File.WriteAllText(String.Format("{0}{1}Bouncy_{2}", dir, Path.DirectorySeparatorChar, name), toSave);
            }
            catch (Exception e)
            {
                ErrorMsg = "Processing bytes using Bouncy Castle RC4 failed: " + e.Message;
                return;
            }
        }

        private void ProcessChaCha20File(object obj)
        {
            ErrorMsg = null;

            byte[] keyByte = KeyAsHex ? CipherKey.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherKey);
            byte[] nonceByte = NonceAsHex ? CipherNonce.Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                : Encoding.UTF8.GetBytes(CipherNonce);
            byte[] textByte;

            try
            {
                textByte = InputFileAsHex ? File.ReadAllText(InputFile).Split('-').Select(b => Convert.ToByte(b, 16)).ToArray()
                    : Encoding.UTF8.GetBytes(File.ReadAllText(InputFile));
            }
            catch
            {
                ErrorMsg = "Selected file is corrupted or missing.";
                return;
            }

            // custom implementation
            try
            {
                var chacha20Engine = new ChaCha20CipherEngine();
                chacha20Engine.Init(keyByte);
                byte[] customOutput = chacha20Engine.ProcessBytes(textByte, nonceByte);

                string toSave = OutputFileAsHex ? BitConverter.ToString(customOutput)
                    : Encoding.UTF8.GetString(customOutput);

                var dir = Path.GetDirectoryName(OutputFile);
                var name = Path.GetFileName(OutputFile);

                File.WriteAllText(String.Format("{0}{1}Custom_{2}", dir, Path.DirectorySeparatorChar, name), toSave);
            }
            catch (Exception e)
            {
                ErrorMsg = "Processing bytes using custom ChaCha20 failed: " + e.Message;
                return;
            }

            // Bouncy castle implementation
            try
            {
                var chacha20Bouncy = new ChaChaEngine();
                chacha20Bouncy.Init(true, new ParametersWithIV(new KeyParameter(keyByte), nonceByte));
                byte[] bouncyCastleOutput = new byte[textByte.Length];
                chacha20Bouncy.ProcessBytes(textByte, 0, textByte.Length, bouncyCastleOutput, 0);

                string toSave = OutputFileAsHex ? BitConverter.ToString(bouncyCastleOutput)
                    : Encoding.UTF8.GetString(bouncyCastleOutput);

                var dir = Path.GetDirectoryName(OutputFile);
                var name = Path.GetFileName(OutputFile);

                File.WriteAllText(String.Format("{0}{1}Bouncy_{2}", dir, Path.DirectorySeparatorChar, name), toSave);
            }
            catch (Exception e)
            {
                ErrorMsg = "Processing bytes using Bouncy Castle ChaCha20 failed: " + e.Message;
                return;
            }
        }

        #endregion
    }
}