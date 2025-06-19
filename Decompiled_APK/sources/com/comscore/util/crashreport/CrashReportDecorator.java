package com.comscore.util.crashreport;

import com.comscore.Analytics;
import com.comscore.PublisherConfiguration;
import com.comscore.util.jni.JniComScoreHelper;
import com.comscore.util.setup.PlatformSetup;
import com.comscore.util.setup.Setup;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/* loaded from: classes.dex */
public class CrashReportDecorator {
    private static final String d = "21193409";
    private static final String e = "9bfbb83ee80ccdee95e73bc93dacd62f";
    private JniComScoreHelper a;
    private String c = null;
    private long b = System.currentTimeMillis();

    public class a {
        String a;
        boolean b;
        int c;
        int d;
        int e;

        public a() {
        }

        public a(String str) {
            String strTrim = str.trim();
            int iIndexOf = strTrim.indexOf(32);
            if (iIndexOf < 0) {
                this.b = false;
                return;
            }
            String strSubstring = strTrim.substring(0, iIndexOf);
            this.a = strSubstring;
            String strReplace = strSubstring.replace(" ", "");
            this.a = strReplace;
            if (strReplace.length() == 0) {
                this.b = false;
                return;
            }
            String strTrim2 = strTrim.substring(iIndexOf + 1, strTrim.length()).trim();
            int iIndexOf2 = strTrim2.indexOf(32);
            if (iIndexOf2 < 0) {
                this.b = false;
                return;
            }
            String strSubstring2 = strTrim2.substring(0, iIndexOf2);
            if (strSubstring2.length() != 2) {
                this.b = false;
                return;
            }
            String strSubstring3 = strSubstring2.substring(0, 1);
            String strSubstring4 = strSubstring2.substring(1, 2);
            this.c = Integer.valueOf(strSubstring3).intValue();
            this.d = Integer.valueOf(strSubstring4).intValue();
            String strTrim3 = strTrim2.substring(2, strTrim2.length()).trim();
            int iIndexOf3 = strTrim3.indexOf(32);
            if (iIndexOf3 < 0) {
                return;
            }
            this.b = "true".equals(strTrim3.substring(0, iIndexOf3));
            this.e = Integer.valueOf(strTrim3.substring(iIndexOf3 + 1, strTrim3.length()).trim()).intValue();
        }
    }

    public CrashReportDecorator(JniComScoreHelper jniComScoreHelper) {
        this.a = jniComScoreHelper;
    }

    private String a() throws NoSuchAlgorithmException {
        a aVarC;
        List<PublisherConfiguration> publisherConfigurations = Analytics.getConfiguration().getPublisherConfigurations();
        if (publisherConfigurations == null || publisherConfigurations.size() == 0) {
            return e;
        }
        PublisherConfiguration publisherConfiguration = publisherConfigurations.get(0);
        String[] deviceIds = this.a.getDeviceIds();
        if (deviceIds != null) {
            for (String str : deviceIds) {
                aVarC = new a(str);
                if (aVarC.b) {
                    break;
                }
            }
            aVarC = null;
        } else {
            aVarC = null;
        }
        if (aVarC == null) {
            aVarC = c();
        }
        StringBuilder sbX = android.support.v4.media.session.a.x(md5(aVarC.a + md5("zutphen2011comScore@" + publisherConfiguration.getPublisherId())), "-cs");
        sbX.append(aVarC.c);
        sbX.append(aVarC.d);
        return sbX.toString();
    }

    private String b() {
        List<PublisherConfiguration> publisherConfigurations = Analytics.getConfiguration().getPublisherConfigurations();
        return (publisherConfigurations == null || publisherConfigurations.size() == 0) ? d : publisherConfigurations.get(0).getPublisherId();
    }

    private a c() {
        if (this.c == null) {
            this.c = UUID.randomUUID().toString();
        }
        a aVar = new a();
        aVar.a = this.c;
        aVar.c = 2;
        return aVar;
    }

    public void fillCrashReport(CrashReport crashReport) {
        Map<String, String> extras = crashReport.getExtras();
        extras.put("c1", "22");
        extras.put("c2", b());
        String applicationName = this.a.getApplicationName();
        if (applicationName == null) {
            applicationName = "";
        }
        extras.put("ns_ap_an", applicationName);
        String osName = this.a.getOsName();
        if (osName == null) {
            osName = "";
        }
        extras.put("ns_ap_pn", osName);
        String runtimeVersion = this.a.getRuntimeVersion();
        if (runtimeVersion == null) {
            runtimeVersion = "";
        }
        extras.put("ns_ap_pv", runtimeVersion);
        extras.put("c12", a());
        extras.put("name", "Application");
        extras.put("ns_ap_ev", "log");
        String deviceModel = this.a.getDeviceModel();
        if (deviceModel == null) {
            deviceModel = "";
        }
        extras.put("ns_ap_device", deviceModel);
        extras.put("ns_ap_id", String.valueOf(this.b));
        String applicationId = this.a.getApplicationId();
        if (applicationId == null) {
            applicationId = "";
        }
        extras.put("ns_ap_bi", applicationId);
        String runtimeName = this.a.getRuntimeName();
        if (runtimeName == null) {
            runtimeName = "";
        }
        extras.put("ns_ap_pfm", runtimeName);
        String osVersion = this.a.getOsVersion();
        if (osVersion == null) {
            osVersion = "";
        }
        extras.put("ns_ap_pfv", osVersion);
        String applicationVersion = this.a.getApplicationVersion();
        if (applicationVersion == null) {
            applicationVersion = "";
        }
        extras.put("ns_ap_ver", applicationVersion);
        PlatformSetup platformSetup = Setup.getPlatformSetup();
        String javaCodeVersion = platformSetup == null ? "" : platformSetup.getJavaCodeVersion();
        if (javaCodeVersion == null) {
            javaCodeVersion = "";
        }
        extras.put("ns_ap_sv", javaCodeVersion);
        extras.put("ns_ap_bv", "");
        extras.put("ns_ap_smv", "");
        extras.put("ns_type", "hidden");
        extras.put("ns_nc", "1");
        extras.put("ns_ap_ar", this.a.getArchitecture());
        extras.put("ns_ap_cfg", "");
        extras.put("ns_ap_env", "");
        extras.put("ns_ap_ais", "");
        extras.put("ns_ap_i7", "");
    }

    public String md5(String str) throws NoSuchAlgorithmException {
        byte[] bytes = str.getBytes();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.reset();
            messageDigest.update(bytes);
            byte[] bArrDigest = messageDigest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : bArrDigest) {
                String hexString = Integer.toHexString(b & 255);
                if (hexString.length() == 1) {
                    sb.append('0');
                }
                sb.append(hexString);
            }
            return ((Object) sb) + "";
        } catch (Exception unused) {
            return null;
        }
    }

    public String sha1(String str) throws NoSuchAlgorithmException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.reset();
            messageDigest.update(str.getBytes("UTF-8"));
            return a(messageDigest.digest());
        } catch (UnsupportedEncodingException e2) {
            e2.printStackTrace();
            return "";
        } catch (NoSuchAlgorithmException e3) {
            e3.printStackTrace();
            return "";
        }
    }

    private String a(byte[] bArr) {
        Formatter formatter = new Formatter();
        for (byte b : bArr) {
            formatter.format("%02x", Byte.valueOf(b));
        }
        String string = formatter.toString();
        formatter.close();
        return string;
    }
}
