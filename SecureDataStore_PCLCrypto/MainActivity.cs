using Android.App;
using Android.Widget;
using Android.OS;
using System;

namespace SecureDataStore_PCLCrypto
{
    [Activity(Label = "@string/ApplicationName", MainLauncher = true, Icon = "@drawable/icon")]
    public class MainActivity : Activity
    {   
        const string password = "MyKey";
        byte[] salt, encryptedString;
        Button encryptBtn, deCryptBtn;
        EditText creditCardText;

        protected override void OnCreate(Bundle bundle)
        {
            base.OnCreate(bundle);
            
            SetContentView (Resource.Layout.Main);

            encryptBtn = FindViewById<Button>(Resource.Id.enCryptBtn);
            deCryptBtn = FindViewById<Button>(Resource.Id.deCryptBtn);
            creditCardText = FindViewById<EditText>(Resource.Id.creditCardText);
            
            encryptBtn.Click += DataCrypto;
            deCryptBtn.Click += DataDecrypt;
            deCryptBtn.Enabled = false;
            salt = DataCryption.CreateSalt(16);
        } 

        //private void CreditCardText_TextChanged(object sender, TextChangedEventArgs e)
        //{
        //    if (e.Text.ToString().Length % 4 == 0)
        //    {
        //        creditCardText.Text.Insert(e.Text.ToString().Length, "8");
        //    }
        //}
        
        private void DataCrypto(object sender, EventArgs e)
        {
            var data = creditCardText.Text;
            encryptedString = DataCryption.EncryptData(data, password, salt);
            DisplayAlert(GetString(Resource.String.encryptTitle), GetString(Resource.String.encryptMessage) + BitConverter.ToString(encryptedString));
            deCryptBtn.Enabled = true;
        }

        private void DataDecrypt(object sender, EventArgs e)
        {
            var DecryptedString = DataCryption.DecryptData(encryptedString, password, salt);
            DisplayAlert(GetString(Resource.String.decryptTitle), GetString(Resource.String.decryptMessage) + DecryptedString);
        }

        private void DisplayAlert(string title, string message)
        {
            var builder = new AlertDialog.Builder(this);
            builder.SetTitle(title);
            builder.SetMessage(message);
            
            builder.SetNeutralButton("OK", (sender, args) =>
            {
                Toast.MakeText(this, "Completed", ToastLength.Long).Show();
            });

            builder.Create().Show();
        }
    }
}

