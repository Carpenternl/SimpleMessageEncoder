using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using SimpleMessageEncoder;

namespace SimpleMessageEncoder
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
            string[] data ="Hello world\nHow Are you?\nI am fine".Split('\n');
            string[] cypher = MyEncryptionClass.EncryptText(data, "yo");
            string[] data2 = MyEncryptionClass.DecryptText(cypher, "yo");
        }
    }
}
