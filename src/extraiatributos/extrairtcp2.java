package extraiatributos;


import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.math3.stat.Frequency;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class extrairtcp2 {

	static NetworkInterface[] array;
	static Path file = Paths.get("weka_input_ftp.arff");

	public static void escreveArquivo (List<String> fluxo) throws IOException {

		//Se o arquivo nÃ£o existe, cria.
		if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
			Files.createFile(file);
		}
		Files.write(file, fluxo, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
	}
	public static void extraindo(JpcapCaptor pcaptor) throws IOException {    	


		SummaryStatistics tam_pacote = new SummaryStatistics();
		SummaryStatistics tam_cabecalho = new SummaryStatistics();
		Frequency codigo_protocolo = new Frequency();

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
		for (Packet packet : pacotes) {

			//IPPacket, aqui ficam os atributos que são comum ao TCP e UDP
			if (packet instanceof IPPacket) {
				
				IPPacket pacote = (IPPacket) packet;
				
				tam_pacote.addValue(pacote.len);
				
				tam_cabecalho.addValue(pacote.header.length);
				
				codigo_protocolo.addValue(((IPPacket) pacote).protocol);
			}
			
			if (packet instanceof TCPPacket) {
				TCPPacket pacote_tcp = (TCPPacket) packet;
				
				//System.out.println(pacote_tcp.dst_port);
			}
			
			//fluxos.add(+comp_pacoteip+ "," +comp_cabecalhotcp+ "," +janelatcp+ "," +payloadtcp+ ",ftp");
			//escreveArquivo(fluxos);
			//System.out.println(comp_pacoteip+ "," +comp_pacoteip2+ "," +comp_pacoteip3+ "," +comp_cabecalhotcp+ "," +comp_cabecalhoudp+ ",web");
			//System.out.println(packet.toString());
			
		}
		
		//Pacote completo - média, desvio padrão, variância, valor máximo;
		double tam_medio_pacote = tam_pacote.getMean();
		double desvio_padrao_pacote = tam_pacote.getStandardDeviation();
		double variancia_pacote = tam_pacote.getVariance();
		double maximo_pacote = tam_pacote.getMax();
		
		//Cabeçalho - média, desvio padrão e variância;
		double tam_medio_cabecalho = tam_cabecalho.getMean();
		double desvio_padrao_cabecalho = tam_cabecalho.getStandardDeviation();
		double variancia_cabecalho = tam_cabecalho.getVariance();
		
		//Número do protocolo - moda
		List<Comparable<?>> moda_protocolo = codigo_protocolo.getMode();
		
		System.out.println("Dados do tamanho do pacote");
		System.out.println(tam_medio_pacote+", "+desvio_padrao_pacote+", "+variancia_pacote+", "+maximo_pacote);
		
		System.out.println("Dados do tamanho do cabeçalho");
		System.out.println(tam_medio_cabecalho+", "+desvio_padrao_cabecalho+", "+variancia_cabecalho);
		
		System.out.println("Moda do protocolo");
		System.out.println(moda_protocolo);
		
		System.out.println("---------------------------------------------------------");
		

	}
}
