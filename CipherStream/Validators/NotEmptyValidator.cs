using System;
using System.Globalization;
using System.Windows.Controls;

namespace CipherStream.Validators
{
    /// <summary>
    /// NotEmptyValidator class.
    /// This class implements ValidationRule.
    /// </summary>
    class NotEmptyValidator : ValidationRule
    {
        #region methods

        /// <summary>
        /// Validate 'value' value.
        /// </summary>
        /// <param name="value">The value which is to be validated.</param>
        /// <param name="cultureInfo">Culture info object.</param>
        /// <returns>Validation result.</returns>
        public override ValidationResult Validate(object value, CultureInfo cultureInfo)
        {
            var strVal = value as string;
            if (String.IsNullOrEmpty(strVal))
            {
                return new ValidationResult(false, "This field can not be empty.");
            }

            return ValidationResult.ValidResult;
        }

        #endregion
    }
}
