package cn.bfy.secret.demo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

import java.util.Map;

import cn.richinfo.secret.EncryptUtils;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView tvResult = (TextView) findViewById(R.id.tv_result);
        //生成秘钥对
        Map<String, byte[]> map = EncryptUtils.generateKeyPair();
        //数据源
        String data = "hello world!";
        StringBuilder result = new StringBuilder();
        result.append("<RSA加解密>");
        result.append("加密前的数据：" + data + "\n");
        String privateData = "";
        result.append("私钥加密后的数据：" + (privateData = EncryptUtils.encryptRSA2HexString(data.getBytes(),
                map.get(EncryptUtils.KEY_PRIVATE), false)) + "\n");
        result.append("公钥解密后的数据：" + new String(EncryptUtils.decryptHexStringRSA(privateData,
                map.get(EncryptUtils.KEY_PUBLIC), true)) + "\n");
        String publicData = "";
        result.append("公钥加密后的数据：" + (publicData = EncryptUtils.encryptRSA2HexString(data.getBytes(),
                map.get(EncryptUtils.KEY_PUBLIC), true)) + "\n");
        result.append("私钥解密后的数据：" + new String(EncryptUtils.decryptHexStringRSA(publicData,
                map.get(EncryptUtils.KEY_PRIVATE), false)) + "\n\n");

        result.append("<AES加解密>");
        result.append("加密前的数据：" + data + "\n");
        String key = "123456";
        String encryptData = EncryptUtils.encryptAES2HexString(data.getBytes(), key.getBytes());
        result.append("加密后的数据：" + encryptData + "\n");
        String decryptData = new String(EncryptUtils.decryptHexStringAES(encryptData, key.getBytes()));
        result.append("解密后的数据：" + decryptData + "\n\n");

        result.append("<DES加解密>");
        result.append("加密前的数据：" + data + "\n");
        key = "123456";
        String encryptData1 = EncryptUtils.encryptDES2HexString(data.getBytes(), key.getBytes());
        result.append("加密后的数据：" + encryptData + "\n");
        String decryptData1 = new String(EncryptUtils.decryptHexStringDES(encryptData, key.getBytes()));
        result.append("解密后的数据：" + decryptData + "\n\n");

        result.append("<HmacSHA256加解密>");
        result.append("加密前的数据：" + data + "\n");
        key = "123456";
        result.append("加密后的数据：" + EncryptUtils.encryptHmacSHA256ToString(data, key) + "\n\n");

        result.append("<SHA256加解密>");
        result.append("加密前的数据：" + data + "\n");
        result.append("加密后的数据：" + EncryptUtils.encryptSHA256ToString(data) + "\n\n");

        result.append("<MD5加解密>");
        result.append("加密前的数据：" + data + "\n");
        key = "123456";
        result.append("加密后的数据：" + EncryptUtils.encryptHmacSHA256ToString(data, key) + "\n\n");

        tvResult.setText(result.toString());

    }
}
