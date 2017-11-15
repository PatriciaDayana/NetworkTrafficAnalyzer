package extraiatributos;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.DecimalFormat;
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
import jpcap.packet.UDPPacket;

public class extrairtcp2 {

    static NetworkInterface[] array;
    static Path file = Paths.get("weka_input_web.arff");

    public static void escreveArquivo(List<String> fluxo) throws IOException {

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
        Frequency numero_srcporttcp = new Frequency();
        Frequency numero_dstporttcp = new Frequency();
        Frequency numero_srcportudp = new Frequency();
        Frequency numero_dstportudp = new Frequency();

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
                numero_srcporttcp.addValue(((TCPPacket) pacote_tcp).src_port);
                numero_dstporttcp.addValue(((TCPPacket) pacote_tcp).dst_port);
            }
            if (packet instanceof UDPPacket) {
                UDPPacket pacote_udp = (UDPPacket) packet;
                numero_srcportudp.addValue(((UDPPacket) pacote_udp).src_port);
                numero_dstportudp.addValue(((UDPPacket) pacote_udp).dst_port);
            }

        }
        
        DecimalFormat dec = new DecimalFormat("###,###,##0.000000"); //ajuste de casas decimais
        
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

        List<Comparable<?>> moda_srcportatcp = numero_srcporttcp.getMode();
        List<Comparable<?>> moda_dstportatcp = numero_dstporttcp.getMode();
        List<Comparable<?>> moda_srcportaudp = numero_srcportudp.getMode();
        List<Comparable<?>> moda_dstportaudp = numero_dstportudp.getMode();

        //Número da porta - moda
        System.out.println("Dados do tamanho do pacote");//testando o DecimalFormat em tam_medio_pacote
        System.out.println((dec.format(tam_medio_pacote))+ ", " + desvio_padrao_pacote + ", " + variancia_pacote + ", " + maximo_pacote);

        System.out.println("Dados do tamanho do cabeçalho");
        System.out.println(tam_medio_cabecalho + ", " + desvio_padrao_cabecalho + ", " + variancia_cabecalho);

        System.out.println("Moda do protocolo");
        System.out.println(moda_protocolo);

        System.out.println("Moda porta src tcp");
        System.out.println(moda_srcportatcp);
        System.out.println("Moda porta dst tcp");
        System.out.println(moda_dstportatcp);

        System.out.println("Moda porta src udp");
        System.out.println(moda_srcportaudp);
        System.out.println("Moda porta dst udp");
        System.out.println(moda_dstportaudp);
        System.out.println("---------------------------------------------------------");
        
        List<String> fluxos = new ArrayList<>();
        fluxos.add(tam_medio_pacote + "," + desvio_padrao_pacote + "," + variancia_pacote + "," + maximo_pacote +
        		tam_medio_cabecalho + "," + desvio_padrao_cabecalho + "," + variancia_cabecalho + ", " +
        		moda_protocolo.get(0) + "," + 
        		moda_dstportatcp + "," + moda_srcportatcp + "," + 
        		moda_dstportaudp + "," + moda_srcportaudp +",ftp");
        escreveArquivo(fluxos);			
        //System.out.println(packet.toString());
    }
}
