package utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.PrintWriter;

public class ArreglarArchivos {

	public static void main(String[] args) {
		try {
			BufferedReader o= new BufferedReader(new FileReader(new File("./data/1-80.csv")));
			PrintWriter w = new PrintWriter(new File("./data/1-80Nuevo.csv"));
			String p=o.readLine();
			while(p!=null) {
				w.append(p+"\n");
				w.flush();
				p=o.readLine();
				p=o.readLine();
			}
			w.close();
			o.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
