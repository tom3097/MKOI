using System;
using System.Windows.Input;

namespace CipherStream.Models
{
    /// <summary>
    /// RelayCommand class.
    /// This class implements ICommand interface.
    /// </summary>
    class RelayCommand : ICommand
    {
        #region fields

        /// <summary>
        /// Action to be executed when the command is fired.
        /// </summary>
        private Action<object> _execute;

        /// <summary>
        /// Condition which is to be fulfilled in order to execute the command.
        /// </summary>
        private Func<object, bool> _canExecute;

        #endregion

        #region properties

        /// <summary>
        /// 'Can execute changed' event handler.
        /// </summary>
        public event EventHandler CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        #endregion

        #region methods

        /// <summary>
        /// RelayCommand class constructor.
        /// </summary>
        /// <param name="execute">Action to be executed when the command is fired.</param>
        /// <param name="canExecute">Condition which is to be fulfilled in order to execute the command.</param>
        public RelayCommand(Action<object> execute, Func<object, bool> canExecute = null)
        {
            _execute = execute;
            _canExecute = canExecute;
        }

        public RelayCommand()
        {
        }

        /// <summary>
        /// Checks whether the command could be executed.
        /// </summary>
        /// <param name="parameter">Command parameter.</param>
        /// <returns>True if command could be executed, false otherwise.</returns>
        public bool CanExecute(object parameter)
        {
            return _canExecute == null || _canExecute(parameter);
        }

        /// <summary>
        /// Executes the command.
        /// </summary>
        /// <param name="parameter">Command parameter.</param>
        public void Execute(object parameter)
        {
            _execute(parameter);
        }

        #endregion
    }
}
