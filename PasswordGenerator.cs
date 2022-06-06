using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace PasswordGenerator
{
    public static class PasswordGenerator
    {
        #region [GeneratePassword]
        /// <summary>
        /// Generates a random password based on the rules passed in the parameters
        /// </summary>
        /// <param name="includeLowercase">Bool to say if lowercase are required</param>
        /// <param name="includeUppercase">Bool to say if uppercase are required</param>
        /// <param name="includeNumeric">Bool to say if numerics are required</param>
        /// <param name="includeSpecial">Bool to say if special characters are required</param>
        /// <param name="includeSpaces">Bool to say if spaces are required</param>
        /// <param name="lengthOfPassword">Length of password required. Should be between 8 and 20</param>
        /// <returns>A randomly generated password with no more than two identical chars concurrently</returns>
        public static string GeneratePassword(bool includeLowercase, bool includeUppercase, bool includeNumeric, bool includeSpecial, bool includeSpaces, int lengthOfPassword)
        {
            #region [Constants]
            const int MAXIMUM_IDENTICAL_CONSECUTIVE_CHARS = 2;
            const string NUMERIC_CHARS = "1234567890";
            const string UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
            const string SPECIAL_CHARS = @"-~`!@#$%^&*_+=|:;',.?";
            const int PASSWORD_LENGTH_MIN = 12;
            const int PASSWORD_LENGTH_MAX = 64;
            #endregion

            if (lengthOfPassword < PASSWORD_LENGTH_MIN || lengthOfPassword > PASSWORD_LENGTH_MAX) return "Password length minimum: 12\nPassword length maximum: 64";

            #region [Generate Allowed Character Set from Params]
            string characterSet = "";
            if (includeLowercase) characterSet += LOWERCASE_CHARS;
            if (includeUppercase) characterSet += UPPERCASE_CHARS;
            if (includeSpaces) characterSet += " ";
            if (includeNumeric) characterSet += NUMERIC_CHARS;
            if (includeSpecial) characterSet += SPECIAL_CHARS;
            #endregion

            char[] passwordArr = new char[lengthOfPassword];
            int characterSetLength = characterSet.Length;

            for (int characterPosition = 0; characterPosition < lengthOfPassword; characterPosition++)
            {
                passwordArr[characterPosition] = characterSet[RandomNumberGenerator.GetInt32(characterSetLength)];

                // check min of 3 chars, check current char to previous 2
                bool hasTwoInARow =
                    characterPosition > MAXIMUM_IDENTICAL_CONSECUTIVE_CHARS
                    && passwordArr[characterPosition] == passwordArr[characterPosition - 1]
                    && passwordArr[characterPosition] == passwordArr[characterPosition - 2];

                // if true, repeat char generation on this position
                if (hasTwoInARow) characterPosition--;
            }

            // create string using null as the joining delimiter for each char in passwordArr
            // verify it is valid; if not, rebuild password
            string password = string.Join(null, passwordArr);
            if (!PasswordGenerator.IsPasswordValid(includeLowercase, includeUppercase, includeNumeric, includeSpecial, includeSpaces, password))
                GeneratePassword(includeLowercase, includeUppercase, includeNumeric, includeSpecial, includeSpaces, lengthOfPassword);
            return password;
        }
        #endregion

        #region [IsPasswordValid]
        /// <summary>
        /// Checks if the password created is valid
        /// </summary>
        /// <param name="includeLowercase">Bool to say if lowercase are required</param>
        /// <param name="includeUppercase">Bool to say if uppercase are required</param>
        /// <param name="includeNumeric">Bool to say if numerics are required</param>
        /// <param name="includeSpecial">Bool to say if special characters are required</param>
        /// <param name="includeSpaces">Bool to say if spaces are required</param>
        /// <param name="password">Generated password</param>
        /// <returns><c>true</c> or <c>false</c> to say if the password is valid or not</returns>
        public static bool IsPasswordValid(bool includeLowercase, bool includeUppercase, bool includeNumeric, bool includeSpecial, bool includeSpaces, string password)
        {
            #region [Constants]
            const string REGEX_LOWERCASE = @"[a-z]";
            const string REGEX_UPPERCASE = @"[A-Z]";
            const string REGEX_NUMERIC = @"[\d]";
            const string REGEX_SPECIAL = @"[-~`!@#$%^&*_+=|:;',.?]";
            #endregion

            #region [Validation]
            bool isLowercaseValid = includeLowercase ? Regex.IsMatch(password, REGEX_LOWERCASE) : !Regex.IsMatch(password, REGEX_LOWERCASE);
            bool isUppercaseValid = includeUppercase ? Regex.IsMatch(password, REGEX_UPPERCASE) : !Regex.IsMatch(password, REGEX_UPPERCASE);
            bool isNumericValid = includeNumeric ? Regex.IsMatch(password, REGEX_NUMERIC) : !Regex.IsMatch(password, REGEX_NUMERIC);
            bool isSpecialValid = includeSpecial ? Regex.IsMatch(password, REGEX_SPECIAL) : !Regex.IsMatch(password, REGEX_SPECIAL);
            bool isSpacesValid = includeSpaces ? Regex.IsMatch(password, @"[\s]") : !Regex.IsMatch(password, @"[\s]");
            #endregion

            return isLowercaseValid && isUppercaseValid && isNumericValid && isSpecialValid && isSpacesValid;
        }
        #endregion
    }
}
