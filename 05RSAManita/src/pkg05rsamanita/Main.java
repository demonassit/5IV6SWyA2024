/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package pkg05rsamanita;

/**
 *
 * @author Alumno
 */

import java.math.BigInteger;
import java.util.*;
import java.io.*;

public class Main {
    
    
    //variables
    int tamprimo;
    BigInteger p, q, n;
    BigInteger fi;
    BigInteger e, d;
    
    
    public Main(int tamprimo){
        this.tamprimo = this.tamprimo;
    }
    
    //un metodo para generar los numeros primos
    public void generarPrimos(){
        p = new BigInteger(tamprimo, 10,
                new Random());
        //p != q
        do q = new BigInteger(tamprimo, 10,
                new Random());
        while(q.compareTo(p) == 0);
    }
    
    //generar las claves
    
    public void generarClaves(){
        // n = p*q
        // fi = (p-1) * (q-1)  
        
        n = p.multiply(q);
        
        //calcular p-1
        fi = p.subtract(BigInteger.valueOf(1));
        
        fi = fi.multiply(
                q.subtract(BigInteger.valueOf(1)));
        
        //calculamos e
        //e debe de ser un coprimo de n tal que 1<e<fi(n)
        
        do e = new BigInteger(2*tamprimo, new Random());
            while( (e.compareTo(fi) != -1) || 
                ( e.gcd(fi).compareTo(
                        BigInteger.valueOf(1)) != 0 ));
        
        //d se calcula de fomr atal que
        // d = e^1 mod fi   osea es el inverso multiplicativo de e
        
        d = e.modInverse(fi);
        
    }
    
    //cifrar
    public BigInteger[] cifrar(String mensaje){
        int i;
        byte[] temp = new byte[1];
        byte[] digitos = mensaje.getBytes();
        
        BigInteger[] bigdigitos = new BigInteger[digitos.length];
        
        //iterar con el mensaje para cifrarlo
        for(i = 0; i < bigdigitos.length; i++){
            temp[0] = digitos[i];
            bigdigitos[i] = new BigInteger(temp);
        }
        
        BigInteger[] cifrado = new BigInteger[bigdigitos.length];
        
        for(i = 0; i < bigdigitos.length; i++){
            //aplico la formula  C = M^e modn
            cifrado[i] = bigdigitos[i].modPow(e, n);
        }
        return cifrado;
    }
    
    //descifrar
    public String descifrar(BigInteger[] cifrado){
        int i;
        
        BigInteger[] descifrado = new BigInteger[cifrado.length];
        
        //aplico la formula  Md = C^d modn
        
       
        
        //iterar con el mensaje para cifrarlo
        for(i = 0; i < descifrado.length; i++){
            descifrado[i] = cifrado[i].modPow(d, n);
        }
        
        char[] charArray = new char[descifrado.length];
        
        for(i = 0; i < charArray.length; i++){
            //vamos a unir todos los caracteres
            charArray[i] = (char)(descifrado[i].intValue());
        }
        return (new String(charArray));
    }

    /**
     * @param args the command line arguments
     * todos deben de ser 3 digitos en adelante
     * 
     * opcion 1
     * Deberan de integrarle ventanas a este calculo de RSA
     * utilizando swing y metodos privados por encapsulamiento
     * para poder calcular y cifrar lo que sea max 1 persona
     * 
     * opcion 2
     * Realizar este mismo algotimo con un JSP y un servicio
     * web mediante el cual tenga un formulario y se calculen
     * los primos y envie el mensaje a cifrar con operaciones de 
     * maximo 2 personas
     * 
     * opcion 3
     * Deberan de realizar un sistema distribuido donde se integren
     * 1 servidor y 2 clientes
     * el cliente 1 debera de calcular en tiempo polinomico sus llaves
     * debera de enviar la generacion de los numeros al c2 para que tambien
     * pueda realizar el calculo en tiempo polimo de sus llaves
     * se deberan de intercambiar las claves para que cifre y descifre 
     * un mensaje 3 personas 
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
    
}
