package tj;

import java.io.File;
import tj.sign.SignatureUtils;
import static tj.sign.SignatureUtils.getZipIn;

/**
 *
 * @author sp00f
 */
public class Tj {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        if (args.length < 3) {
            System.err.printf("this tool needs  3 parameters"
                    + "\njava -jar tj.jar  [1] [2] [3]\n"
                    + "1: apkpath \n"
                    + "2: certpath in zip\n"
                    + "3: sign file path to save");
            
            System.exit(-1);
        }

        String apkpath = args[0];
        String certpath = args[1];
        String certsavepath = args[2];

        System.out.println("apkpath = " + apkpath + "\ncertpath = " + certpath + "\ncertsavepath = " + certsavepath);

        try {
            String sign = SignatureUtils.xchSignBytesToStr(SignatureUtils.getZipIn(apkpath, certpath));
            SignatureUtils.writeSignStrToFile(new File(certsavepath), sign);
        } catch (Exception e) {
            System.err.println("parse apk sign fail!\n" + e);
        }
    }

}
