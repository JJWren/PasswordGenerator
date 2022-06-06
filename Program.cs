namespace PasswordGenerator
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var password = PasswordGenerator.GeneratePassword(true, true, true, true, true, 20);
            Console.WriteLine(password);
        }
    }
}