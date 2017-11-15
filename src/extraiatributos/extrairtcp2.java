package extraiatributos;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
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
import jpcap.packet.UDPPacket;

public class extrairtcp2 {

    static NetworkInterface[] array;
    static Path file = Paths.get("weka_input_web.arff");

    public static void escreveArquivo(List<String> fluxo) throws IOException {

        //Se o arquivo n√É¬£o existe, cria.
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            Files.createFile(file);
        }
        Files.write(file, fluxo, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
    }

    public static void extraindo(JpcapCaptor pcaptor) throws IOException {

        SummaryStatistics tam_pacote = new SummaryStatistics();
        SummaryStatistics tam_cabecalho = new SummaryStatistics();
        Frequency codigo_protocolo = new Frequency();
        /*
        Frequency numero_srcporttcp = new Frequency();
        Frequency numero_dstporttcp = new Frequency();
        Frequency numero_srcportudp = new Frequency();
        Frequency numero_dstportudp = new Frequency();
        */
        
        //ModificaÁ„o sugerida. N„o fazer distinÁ„o da vari·vel de n˙mero de porta por protocolo, TCP e UDP possuem porta.
        Frequency numero_srcport = new Frequency();
        Frequency numero_dstport = new Frequency();

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

            //IPPacket, aqui ficam os atributos que s√£o comum ao TCP e UDP
            if (packet instanceof IPPacket) {

                IPPacket pacote = (IPPacket) packet;

                tam_pacote.addValue(pacote.len);

                tam_cabecalho.addValue(pacote.header.length);

                codigo_protocolo.addValue(((IPPacket) pacote).protocol);

            }

            if (packet instanceof TCPPacket) {
                TCPPacket pacote_tcp = (TCPPacket) packet;
                //numero_srcporttcp.addValue(((TCPPacket) pacote_tcp).src_port);
                //numero_dstporttcp.addValue(((TCPPacket) pacote_tcp).dst_port);
                
                //ModificaÁ„o sugerida.
                numero_srcport.addValue(((TCPPacket) pacote_tcp).src_port);
                numero_dstport.addValue(((TCPPacket) pacote_tcp).dst_port);
            }
            if (packet instanceof UDPPacket) {
                UDPPacket pacote_udp = (UDPPacket) packet;
                //numero_srcportudp.addValue(((UDPPacket) pacote_udp).src_port);
                //numero_dstportudp.addValue(((UDPPacket) pacote_udp).dst_port);
                
                //ModificaÁ„o sugerida.
                numero_srcport.addValue(((UDPPacket) pacote_udp).src_port);
                numero_dstport.addValue(((UDPPacket) pacote_udp).dst_port);
            }

        }
                
        //Pacote completo - m√©dia, desvio padr√£o, vari√¢ncia, valor m√°ximo;
        double tam_medio_pacote = tam_pacote.getMean();
        double desvio_padrao_pacote = tam_pacote.getStandardDeviation();
        double variancia_pacote = tam_pacote.getVariance();
        double maximo_pacote = tam_pacote.getMax();

        //Cabe√ßalho - m√©dia, desvio padr√£o e vari√¢ncia;
        double tam_medio_cabecalho = tam_cabecalho.getMean();
        double desvio_padrao_cabecalho = tam_cabecalho.getStandardDeviation();
        double variancia_cabecalho = tam_cabecalho.getVariance();

        //N√∫mero do protocolo - moda
        List<Comparable<?>> moda_protocolo = codigo_protocolo.getMode();

        //List<Comparable<?>> moda_srcportatcp = numero_srcporttcp.getMode();
        //List<Comparable<?>> moda_dstportatcp = numero_dstporttcp.getMode();
        //List<Comparable<?>> moda_srcportaudp = numero_srcportudp.getMode();
        //List<Comparable<?>> moda_dstportaudp = numero_dstportudp.getMode();
        
        //ModificaÁ„o sugerida.
        List<Comparable<?>> moda_srcporta = numero_srcport.getMode();
        List<Comparable<?>> moda_dstporta = numero_dstport.getMode();

        //N√∫mero da porta - moda
        System.out.println("Dados do tamanho do pacote");
        //System.out.println(tam_medio_pacote+ ", " + desvio_padrao_pacote + ", " + variancia_pacote + ", " + maximo_pacote);
        BigDecimal tmp = new BigDecimal(tam_medio_pacote).setScale(5, RoundingMode.HALF_EVEN);
        BigDecimal dpp = new BigDecimal(desvio_padrao_pacote).setScale(5, RoundingMode.HALF_EVEN);
        BigDecimal vp = new BigDecimal(variancia_pacote).setScale(5, RoundingMode.HALF_EVEN);
        BigDecimal mp = new BigDecimal(maximo_pacote).setScale(5, RoundingMode.HALF_EVEN);
        System.out.println(tmp.doubleValue());
        System.out.println(dpp.doubleValue());
        System.out.println(vp.doubleValue());
        System.out.println(mp.doubleValue());
    

        System.out.println("Dados do tamanho do cabe√ßalho");
       // System.out.println(tam_medio_cabecalho + ", " + desvio_padrao_cabecalho + ", " + variancia_cabecalho);
        BigDecimal tmc = new BigDecimal(tam_medio_cabecalho).setScale(5, RoundingMode.HALF_EVEN);
        BigDecimal dpc = new BigDecimal(desvio_padrao_cabecalho).setScale(5, RoundingMode.HALF_EVEN);
        BigDecimal vc = new BigDecimal(variancia_cabecalho).setScale(5, RoundingMode.HALF_EVEN);
        System.out.println(tmc.doubleValue());
        System.out.println(dpc.doubleValue());
        System.out.println(vc.doubleValue());
        

        System.out.println("Moda do protocolo");
        System.out.println(moda_protocolo);
        
        /*
        System.out.println("Moda porta src tcp");
        System.out.println(moda_srcportatcp);
        System.out.println("Moda porta dst tcp");
        System.out.println(moda_dstportatcp);

        System.out.println("Moda porta src udp");
        System.out.println(moda_srcportaudp);
        System.out.println("Moda porta dst udp");
        System.out.println(moda_dstportaudp);
        */
        
        System.out.println("Moda porta src");
        System.out.println(moda_srcporta);
        System.out.println("Moda porta dst");
        System.out.println(moda_dstporta);
        
        System.out.println("---------------------------------------------------------");
        
        List<String> fluxos = new ArrayList<>();
        /*fluxos.add(tmp + "," + dpp + "," + vp + "," + mp +
        		tmc + "," + dpc + "," + vc + ", " +
        		moda_protocolo.get(0) + "," + 
        		moda_dstportatcp.get(0) + "," + moda_srcportatcp.get(0) + "," + 
        		moda_dstportaudp.get(0) + "," + moda_srcportaudp.get(0) +",ftp");
        */
        
        fluxos.add(
        		tmp + "," + dpp + "," + vp + "," + mp +
        		tmc + "," + dpc + "," + vc + ", " +
        		moda_protocolo.get(0) + "," + 
        		moda_dstporta.get(0) + "," + moda_srcporta.get(0) + 
        		",ftp"
        		);
        escreveArquivo(fluxos);			
        //System.out.println(packet.toString());
    }
}
