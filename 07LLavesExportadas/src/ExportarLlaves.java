/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */

/**
 *
 * @author Alumno
 */
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;

public class ExportarLlaves {

    private static Cipher rsa;
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        // TODO code application logic here
        
        /*
        Vamos a generar un codigo para poder exportar
        como llaves independientes puyblica y privada
        para poder firmar un documento
        */
        
        KeyPairGenerator generadorllaves = 
                KeyPairGenerator.getInstance("RSA");
        KeyPair llavesrsa = generadorllaves.generateKeyPair();
        
        //generamos publica y privada
        PublicKey llavepublica = llavesrsa.getPublic();
        PrivateKey llaveprivada = llavesrsa.getPrivate();
        
        //ahora para poder firma un documento se debe de hacer uso
        //del algoritmo de rsa con un hash
        
        //metodos para guardar y cargar
        saveKey(llavepublica, "public.key");
        llavepublica = loadpublickey("public.key");
        
        
        saveKey(llaveprivada, "private.key");
        llaveprivada = loadprivatekey("private.key");
        
        rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        String text = "Habia una vez un patito que decia miau miau";
        
        //ciframos
        rsa.init(Cipher.ENCRYPT_MODE, llavepublica);
        
        //vamos a dar formato al cifrado
        byte[] cifrado = rsa.doFinal(text.getBytes());
        
        //imprimos lo que dice el cifrado
        for(byte b : cifrado){
            System.out.print(Integer.toHexString(0xFF & b));
        }
        System.out.println("");
        
        //descifrar
        rsa.init(Cipher.DECRYPT_MODE, llaveprivada);
        byte[] bytesdescifrados = rsa.doFinal(cifrado);
        String textodescifrado = new String(bytesdescifrados);
        System.out.println("Mensaje Descifrado es: " + textodescifrado);
        
    }

    private static void saveKey(Key llave, String archivo) throws Exception{
        byte[] llavesPubPriv = llave.getEncoded();
        //genero el archivo
        FileOutputStream fos = new FileOutputStream(archivo);
        fos.write(llavesPubPriv);
        fos.close();
    }

    private static PublicKey loadpublickey(String archivo) throws Exception{
        FileInputStream fis = new FileInputStream(archivo);
        int numbytes = fis.available();
        byte[] bytes = new byte[numbytes];
        fis.read(bytes);
        fis.close();
        
        //tenemos que verificar que la clave de la llave sea valida
        KeyFactory fabricallaves = KeyFactory.getInstance("RSA");
        //ahora vamos a comparar la llave
        KeySpec keyspec = new X509EncodedKeySpec(bytes);
        PublicKey llavedelarchivo = fabricallaves.generatePublic(keyspec);
        return llavedelarchivo;
    }

    private static PrivateKey loadprivatekey(String archivo) throws Exception{
        FileInputStream fis = new FileInputStream(archivo);
        int numbytes = fis.available();
        byte[] bytes = new byte[numbytes];
        fis.read(bytes);
        fis.close();
        
        //tenemos que verificar que la clave de la llave sea valida
        KeyFactory fabricallaves = KeyFactory.getInstance("RSA");
        //ahora vamos a comparar la llave
        KeySpec keyspec = new PKCS8EncodedKeySpec(bytes);
        PrivateKey llavedelarchivopriv = 
                fabricallaves.generatePrivate(keyspec);
        return llavedelarchivopriv;
    }
    
}
