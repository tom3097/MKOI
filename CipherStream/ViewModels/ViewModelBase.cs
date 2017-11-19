using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace CipherStream.ViewModels
{
    /// <summary>
    /// ViewModelBase class.
    /// This class implements INotifyPropertyChanged interface.
    /// </summary>
    public abstract class ViewModelBase : INotifyPropertyChanged
    {
        #region properties

        /// <summary>
        /// PropertyChanged event handler.
        /// </summary>
        public event PropertyChangedEventHandler PropertyChanged;

        #endregion

        #region methods

        /// <summary>
        /// Sets property value and notifies the application.
        /// </summary>
        /// <typeparam name="T">Propertie's type.</typeparam>
        /// <param name="storage">Property to be updated.</param>
        /// <param name="value">New property's value.</param>
        /// <param name="propertyName">Property name automatically obtained.</param>
        /// <returns></returns>
        protected virtual bool SetProperty<T>(ref T storage, T value, [CallerMemberName] string propertyName = "")
        {
            if (EqualityComparer<T>.Default.Equals(storage, value))
                return false;
            storage = value;
            OnPropertyChanged(propertyName);
            return true;
        }

        /// <summary>
        /// Notifies the application about the update of the 'propertyName' property.
        /// </summary>
        /// <param name="propertyName">The name of the property to be updated.</param>
        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion
    }
}
