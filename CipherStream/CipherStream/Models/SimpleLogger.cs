using System;
using System.IO;
using System.Text;

namespace CipherStream.Models
{
    class SimpleLogger
    {
        #region fields

        /// <summary>
        /// Path to log file.
        /// </summary>
        private readonly string _logFile;

        /// <summary>
        /// StringBuilder containing text to be written to the log file.
        /// </summary>
        private readonly StringBuilder _log;

        #endregion

        #region methods

        /// <summary>
        /// Creates SimpleLogger object with associated log file.
        /// </summary>
        /// <param name="logFile"></param>
        public SimpleLogger(string logFile)
        {
            _logFile = logFile;
            _log = new StringBuilder();
        }

        /// <summary>
        /// Append log message to log buffer.
        /// </summary>
        /// <param name="logMessage"></param>
        public void Log(string logMessage)
        {
            _log.Append(DateTime.Now.ToString("[yyyy-MM-dd HH:mm:ss.fff] "));
            _log.Append(logMessage);
            _log.AppendLine();
        }

        /// <summary>
        /// Save logs to a file.
        /// </summary>
        public void Save()
        {
            File.WriteAllText(_logFile, _log.ToString());
            _log.Clear();
        }

        #endregion
    }
}
