using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Caching;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class Class1
    {
        public static string GetToken()
        {
            ObjectCache oCache = MemoryCache.Default;
            string fileContents = oCache["wechart_token"] as string;
            if (fileContents == null)
            {
                CacheItemPolicy policy = new CacheItemPolicy();
                policy.AbsoluteExpiration = DateTime.Now.AddMinutes(120);//取得或设定值，这个值会指定是否应该在指定期间过后清除
                fileContents = null;//这里赋值;
              
                oCache.Set("wechart_token", fileContents, policy);
            }
            //Install - Package Autofac - Version 4.6.0
            return fileContents;
        }
    }
}
