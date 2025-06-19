package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import androidx.compose.material3.C0676l1;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.ads.q5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2514q5 {
    public static final ArrayList a = new ArrayList();
    public static final Pattern b = Pattern.compile("^mp4a\\.([a-zA-Z0-9]{2})(?:\\.([0-9]{1,2}))?$");

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:41:0x008e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int a(java.lang.String r7, java.lang.String r8) {
        /*
            int r0 = r7.hashCode()
            r1 = 6
            r2 = 5
            r3 = 9
            r4 = 7
            r5 = 8
            r6 = 0
            switch(r0) {
                case -2123537834: goto L84;
                case -1365340241: goto L7a;
                case -1095064472: goto L70;
                case -53558318: goto L66;
                case 187078296: goto L5c;
                case 187078297: goto L52;
                case 550520934: goto L48;
                case 1504578661: goto L3e;
                case 1504831518: goto L34;
                case 1504891608: goto L28;
                case 1505942594: goto L1d;
                case 1556697186: goto L11;
                default: goto Lf;
            }
        Lf:
            goto L8e
        L11:
            java.lang.String r0 = "audio/true-hd"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = 10
            goto L8f
        L1d:
            java.lang.String r0 = "audio/vnd.dts.hd"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = r4
            goto L8f
        L28:
            java.lang.String r0 = "audio/opus"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = 11
            goto L8f
        L34:
            java.lang.String r0 = "audio/mpeg"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = r6
            goto L8f
        L3e:
            java.lang.String r0 = "audio/eac3"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = 3
            goto L8f
        L48:
            java.lang.String r0 = "audio/vnd.dts.uhd;profile=p2"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = r3
            goto L8f
        L52:
            java.lang.String r0 = "audio/ac4"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = r2
            goto L8f
        L5c:
            java.lang.String r0 = "audio/ac3"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = 2
            goto L8f
        L66:
            java.lang.String r0 = "audio/mp4a-latm"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = 1
            goto L8f
        L70:
            java.lang.String r0 = "audio/vnd.dts"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = r1
            goto L8f
        L7a:
            java.lang.String r0 = "audio/vnd.dts.hd;profile=lbr"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = r5
            goto L8f
        L84:
            java.lang.String r0 = "audio/eac3-joc"
            boolean r7 = r7.equals(r0)
            if (r7 == 0) goto L8e
            r7 = 4
            goto L8f
        L8e:
            r7 = -1
        L8f:
            switch(r7) {
                case 0: goto Lb5;
                case 1: goto La6;
                case 2: goto La5;
                case 3: goto La4;
                case 4: goto La1;
                case 5: goto L9e;
                case 6: goto L9d;
                case 7: goto L9c;
                case 8: goto L9c;
                case 9: goto L99;
                case 10: goto L96;
                case 11: goto L93;
                default: goto L92;
            }
        L92:
            return r6
        L93:
            r7 = 20
            return r7
        L96:
            r7 = 14
            return r7
        L99:
            r7 = 30
            return r7
        L9c:
            return r5
        L9d:
            return r4
        L9e:
            r7 = 17
            return r7
        La1:
            r7 = 18
            return r7
        La4:
            return r1
        La5:
            return r2
        La6:
            if (r8 != 0) goto La9
            return r6
        La9:
            androidx.compose.material3.l1 r7 = c(r8)
            if (r7 != 0) goto Lb0
            return r6
        Lb0:
            int r7 = r7.c()
            return r7
        Lb5:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2514q5.a(java.lang.String, java.lang.String):int");
    }

    public static int b(String str) {
        if (TextUtils.isEmpty(str)) {
            return -1;
        }
        if (h(str)) {
            return 1;
        }
        if (j(str)) {
            return 2;
        }
        if ("text".equals(k(str)) || "application/x-media3-cues".equals(str) || "application/cea-608".equals(str) || "application/cea-708".equals(str) || "application/x-mp4-cea-608".equals(str) || "application/x-subrip".equals(str) || "application/ttml+xml".equals(str) || "application/x-quicktime-tx3g".equals(str) || "application/x-mp4-vtt".equals(str) || "application/x-rawcc".equals(str) || "application/vobsub".equals(str) || "application/pgs".equals(str) || "application/dvbsubs".equals(str)) {
            return 3;
        }
        if (i(str)) {
            return 4;
        }
        if ("application/id3".equals(str) || "application/x-emsg".equals(str) || "application/x-scte35".equals(str) || "application/x-icy".equals(str) || "application/vnd.dvb.ait".equals(str)) {
            return 5;
        }
        if ("application/x-camera-motion".equals(str)) {
            return 6;
        }
        ArrayList arrayList = a;
        if (arrayList.size() <= 0) {
            return -1;
        }
        arrayList.get(0).getClass();
        throw new ClassCastException();
    }

    public static C0676l1 c(String str) {
        Matcher matcher = b.matcher(str);
        if (!matcher.matches()) {
            return null;
        }
        String strGroup = matcher.group(1);
        strGroup.getClass();
        String strGroup2 = matcher.group(2);
        try {
            return new C0676l1(Integer.parseInt(strGroup, 16), strGroup2 != null ? Integer.parseInt(strGroup2) : 0, false);
        } catch (NumberFormatException unused) {
            return null;
        }
    }

    public static String d(int i) {
        if (i == 32) {
            return "video/mp4v-es";
        }
        if (i == 33) {
            return "video/avc";
        }
        if (i == 35) {
            return "video/hevc";
        }
        if (i == 64) {
            return "audio/mp4a-latm";
        }
        if (i == 163) {
            return "video/wvc1";
        }
        if (i == 177) {
            return "video/x-vnd.on2.vp9";
        }
        if (i == 221) {
            return "audio/vorbis";
        }
        if (i == 165) {
            return "audio/ac3";
        }
        if (i == 166) {
            return "audio/eac3";
        }
        switch (i) {
            case 96:
            case 97:
            case 98:
            case 99:
            case 100:
            case 101:
                return "video/mpeg2";
            case 102:
            case 103:
            case 104:
                return "audio/mp4a-latm";
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED /* 105 */:
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED /* 107 */:
                return "audio/mpeg";
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF /* 106 */:
                return "video/mpeg";
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY /* 108 */:
                return "image/jpeg";
            default:
                switch (i) {
                    case 169:
                    case 172:
                        return "audio/vnd.dts";
                    case 170:
                    case 171:
                        return "audio/vnd.dts.hd";
                    case 173:
                        return "audio/opus";
                    case 174:
                        return "audio/ac4";
                    default:
                        return null;
                }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0056  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String e(java.lang.String r1) {
        /*
            if (r1 != 0) goto L4
            r1 = 0
            return r1
        L4:
            java.lang.String r1 = com.google.android.gms.internal.ads.AbstractC2543qs.f(r1)
            int r0 = r1.hashCode()
            switch(r0) {
                case -1833600100: goto L4c;
                case -1007807498: goto L42;
                case -979095690: goto L38;
                case -586683234: goto L2e;
                case -432836268: goto L24;
                case -432836267: goto L1a;
                case 187090231: goto L10;
                default: goto Lf;
            }
        Lf:
            goto L56
        L10:
            java.lang.String r0 = "audio/mp3"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L56
            r0 = 2
            goto L57
        L1a:
            java.lang.String r0 = "audio/mpeg-l2"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L56
            r0 = 6
            goto L57
        L24:
            java.lang.String r0 = "audio/mpeg-l1"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L56
            r0 = 5
            goto L57
        L2e:
            java.lang.String r0 = "audio/x-wav"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L56
            r0 = 3
            goto L57
        L38:
            java.lang.String r0 = "application/x-mpegurl"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L56
            r0 = 4
            goto L57
        L42:
            java.lang.String r0 = "audio/x-flac"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L56
            r0 = 1
            goto L57
        L4c:
            java.lang.String r0 = "video/x-mvhevc"
            boolean r0 = r1.equals(r0)
            if (r0 == 0) goto L56
            r0 = 0
            goto L57
        L56:
            r0 = -1
        L57:
            switch(r0) {
                case 0: goto L6d;
                case 1: goto L6a;
                case 2: goto L67;
                case 3: goto L64;
                case 4: goto L61;
                case 5: goto L5e;
                case 6: goto L5b;
                default: goto L5a;
            }
        L5a:
            return r1
        L5b:
            java.lang.String r1 = "audio/mpeg-L2"
            return r1
        L5e:
            java.lang.String r1 = "audio/mpeg-L1"
            return r1
        L61:
            java.lang.String r1 = "application/x-mpegURL"
            return r1
        L64:
            java.lang.String r1 = "audio/wav"
            return r1
        L67:
            java.lang.String r1 = "audio/mpeg"
            return r1
        L6a:
            java.lang.String r1 = "audio/flac"
            return r1
        L6d:
            java.lang.String r1 = "video/mv-hevc"
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2514q5.e(java.lang.String):java.lang.String");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0081  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean f(java.lang.String r3, java.lang.String r4) {
        /*
            r0 = 0
            if (r3 != 0) goto L4
            return r0
        L4:
            int r1 = r3.hashCode()
            r2 = 1
            switch(r1) {
                case -2123537834: goto L76;
                case -432837260: goto L6c;
                case -432837259: goto L62;
                case -53558318: goto L57;
                case 187078296: goto L4d;
                case 187094639: goto L43;
                case 1504578661: goto L38;
                case 1504619009: goto L2e;
                case 1504831518: goto L24;
                case 1903231877: goto L19;
                case 1903589369: goto Le;
                default: goto Lc;
            }
        Lc:
            goto L81
        Le:
            java.lang.String r1 = "audio/g711-mlaw"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 5
            goto L82
        L19:
            java.lang.String r1 = "audio/g711-alaw"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 4
            goto L82
        L24:
            java.lang.String r1 = "audio/mpeg"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = r0
            goto L82
        L2e:
            java.lang.String r1 = "audio/flac"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 6
            goto L82
        L38:
            java.lang.String r1 = "audio/eac3"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 8
            goto L82
        L43:
            java.lang.String r1 = "audio/raw"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 3
            goto L82
        L4d:
            java.lang.String r1 = "audio/ac3"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 7
            goto L82
        L57:
            java.lang.String r1 = "audio/mp4a-latm"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 10
            goto L82
        L62:
            java.lang.String r1 = "audio/mpeg-L2"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 2
            goto L82
        L6c:
            java.lang.String r1 = "audio/mpeg-L1"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = r2
            goto L82
        L76:
            java.lang.String r1 = "audio/eac3-joc"
            boolean r3 = r3.equals(r1)
            if (r3 == 0) goto L81
            r3 = 9
            goto L82
        L81:
            r3 = -1
        L82:
            switch(r3) {
                case 0: goto L9c;
                case 1: goto L9c;
                case 2: goto L9c;
                case 3: goto L9c;
                case 4: goto L9c;
                case 5: goto L9c;
                case 6: goto L9c;
                case 7: goto L9c;
                case 8: goto L9c;
                case 9: goto L9c;
                case 10: goto L86;
                default: goto L85;
            }
        L85:
            return r0
        L86:
            if (r4 != 0) goto L89
            return r0
        L89:
            androidx.compose.material3.l1 r3 = c(r4)
            if (r3 != 0) goto L90
            return r0
        L90:
            int r3 = r3.c()
            if (r3 == 0) goto L9b
            r4 = 16
            if (r3 == r4) goto L9b
            return r2
        L9b:
            return r0
        L9c:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2514q5.f(java.lang.String, java.lang.String):boolean");
    }

    public static boolean g(String str, String str2) {
        String strD;
        C0676l1 c0676l1C;
        String string = null;
        if (str != null) {
            String str3 = Yo.a;
            String[] strArrSplit = TextUtils.isEmpty(str) ? new String[0] : str.trim().split("(\\s*,\\s*)", -1);
            StringBuilder sb = new StringBuilder();
            for (String str4 : strArrSplit) {
                if (str4 == null) {
                    strD = null;
                } else {
                    String strF = AbstractC2543qs.f(str4.trim());
                    if (strF.startsWith("avc1") || strF.startsWith("avc3")) {
                        strD = "video/avc";
                    } else if (strF.startsWith("hev1") || strF.startsWith("hvc1")) {
                        strD = "video/hevc";
                    } else if (strF.startsWith("dvav") || strF.startsWith("dva1") || strF.startsWith("dvhe") || strF.startsWith("dvh1")) {
                        strD = "video/dolby-vision";
                    } else if (strF.startsWith("av01")) {
                        strD = "video/av01";
                    } else if (strF.startsWith("vp9") || strF.startsWith("vp09")) {
                        strD = "video/x-vnd.on2.vp9";
                    } else if (strF.startsWith("vp8") || strF.startsWith("vp08")) {
                        strD = "video/x-vnd.on2.vp8";
                    } else if (strF.startsWith("mp4a")) {
                        strD = (!strF.startsWith("mp4a.") || (c0676l1C = c(strF)) == null) ? null : d(c0676l1C.a);
                        if (strD == null) {
                            strD = "audio/mp4a-latm";
                        }
                    } else if (strF.startsWith("mha1")) {
                        strD = "audio/mha1";
                    } else if (strF.startsWith("mhm1")) {
                        strD = "audio/mhm1";
                    } else if (strF.startsWith("ac-3") || strF.startsWith("dac3")) {
                        strD = "audio/ac3";
                    } else if (strF.startsWith("ec-3") || strF.startsWith("dec3")) {
                        strD = "audio/eac3";
                    } else if (strF.startsWith("ec+3")) {
                        strD = "audio/eac3-joc";
                    } else if (strF.startsWith("ac-4") || strF.startsWith("dac4")) {
                        strD = "audio/ac4";
                    } else if (strF.startsWith("dtsc")) {
                        strD = "audio/vnd.dts";
                    } else if (strF.startsWith("dtse")) {
                        strD = "audio/vnd.dts.hd;profile=lbr";
                    } else if (strF.startsWith("dtsh") || strF.startsWith("dtsl")) {
                        strD = "audio/vnd.dts.hd";
                    } else if (strF.startsWith("dtsx")) {
                        strD = "audio/vnd.dts.uhd;profile=p2";
                    } else if (strF.startsWith("opus")) {
                        strD = "audio/opus";
                    } else if (strF.startsWith("vorbis")) {
                        strD = "audio/vorbis";
                    } else if (strF.startsWith("flac")) {
                        strD = "audio/flac";
                    } else if (strF.startsWith("stpp")) {
                        strD = "application/ttml+xml";
                    } else if (strF.startsWith("wvtt")) {
                        strD = "text/vtt";
                    } else if (strF.contains("cea708")) {
                        strD = "application/cea-708";
                    } else if (strF.contains("eia608") || strF.contains("cea608")) {
                        strD = "application/cea-608";
                    } else {
                        ArrayList arrayList = a;
                        if (arrayList.size() > 0) {
                            arrayList.get(0).getClass();
                            throw new ClassCastException();
                        }
                        strD = null;
                    }
                }
                if (str2.equals(strD)) {
                    if (sb.length() > 0) {
                        sb.append(",");
                    }
                    sb.append(str4);
                }
            }
            if (sb.length() > 0) {
                string = sb.toString();
            }
        }
        return string != null;
    }

    public static boolean h(String str) {
        return "audio".equals(k(str));
    }

    public static boolean i(String str) {
        return "image".equals(k(str)) || "application/x-image-uri".equals(str);
    }

    public static boolean j(String str) {
        return com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO.equals(k(str));
    }

    public static String k(String str) {
        int iIndexOf;
        if (str == null || (iIndexOf = str.indexOf(47)) == -1) {
            return null;
        }
        return str.substring(0, iIndexOf);
    }
}
