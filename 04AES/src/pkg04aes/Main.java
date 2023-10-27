/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package pkg04aes;

/**
 *
 * @author Alumno
 */
import java.io.UnsupportedEncodingException;
import java.security.*;
import javax.crypto.*;
import java.util.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    static String texto = "Habia una vez un patito que decia miau miau";
    static String llave = "asdfghjkiuytrew0";
    static String vector = "asdfghjkiuytrewq";
    

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        // TODO code application logic here
        
        System.out.println("Ejemplo AES");
        System.out.println("Texto a cifrar: " + texto);
        
        //declara un arreglo de bytes
        byte[] cifrado = encrypt(texto, llave);
        
        System.out.println("Texto cifrado");
        for(int i = 0; i < cifrado.length; i++)
           System.out.print(new Integer(
                   cifrado[i]));
        
        System.out.println();
        
        String decifrar = decrypt(cifrado, llave);
        
        System.out.println("Texto descifrado: " 
                + decifrar);
    
    
    }   

    public static byte[] encrypt(String texto, String llave) throws Exception {
        Cipher cifradoaes = 
                Cipher.getInstance(
                        "AES/CBC/PKCS5Padding",
                        "SunJCE");
        
        //generamos las llaves
        SecretKeySpec key =new SecretKeySpec(
                llave.getBytes("UTF-8"),
                "AES");
        
        //inicializar el modo
        cifradoaes.init(Cipher.ENCRYPT_MODE, 
                key, new IvParameterSpec(
                vector.getBytes("UTF-8")));
        return cifradoaes.doFinal(
                texto.getBytes("UTF-8"));
    }

    public static String decrypt(byte[] cifrado, String llave) throws Exception {
        Cipher cifradoaes = 
                Cipher.getInstance(
                        "AES/CBC/PKCS5Padding",
                        "SunJCE");
        
        //generamos las llaves
        SecretKeySpec key =new SecretKeySpec(
                llave.getBytes("UTF-8"),
                "AES");
        
        //inicializar el modo
        cifradoaes.init(Cipher.DECRYPT_MODE, 
                key, new IvParameterSpec(
                vector.getBytes("UTF-8")));
        return new String(cifradoaes.doFinal(
                cifrado), "UTF-8");
    
    }
    
}
