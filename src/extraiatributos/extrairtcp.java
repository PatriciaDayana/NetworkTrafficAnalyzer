package extraiatributos;


import java.io.IOException;
import java.lang.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class extrairtcp {

	static NetworkInterface[] array;
	static Path file = Paths.get("weka_input_web.arff");

	public static void escreveArquivo (List<String> fluxo) throws IOException {

		//Se o arquivo não existe, cria.
		if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
			Files.createFile(file);
		}
		Files.write(file, fluxo, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
	}
	public static void extraindo(JpcapCaptor pcaptor) throws IOException {    	

		int janela = 0;
		int payload = 0;  
		int comp_cabecalhotcp = 0;
		int comp_pacote = 0;

		List<String> fluxos = new ArrayList<>();

		//lista para receber os pacotes
		final List<Packet> pacotes = new ArrayList<>();
		pcaptor.loopPacket(-1, new PacketReceiver() {
			@Override
			public void receivePacket(Packet packet) {
				if (packet instanceof IPPacket) {
					pacotes.add(packet);
				}
			}
		});

		//percorrendo a lista de pacotes para calcular os atributos
		int contador = 0;
		for (Packet packet : pacotes) {

			if (packet instanceof TCPPacket) {
				TCPPacket tcp = (TCPPacket) packet;

				//obtem o Tamanho da janela
				janela = janela + tcp.window;

				//obtem o tamanho do payload
				payload = payload + tcp.data.length;

				//obtem o comprimento do cabecalho TCP 
				comp_cabecalhotcp = comp_cabecalhotcp + tcp.header.length;

				//obtem o comprimento do pacote IP
				comp_pacote = comp_pacote + tcp.length;


				contador++;
			}


		}


		fluxos.add(+janela+ "," +payload+ "," +comp_cabecalhotcp+ "," +comp_pacote+ ",p2p");
		escreveArquivo(fluxos);
	}
}
