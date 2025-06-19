package com.google.android.gms.internal.ads;

import android.app.UiModeManager;
import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import com.comscore.streaming.AdvertisementType;
import com.comscore.streaming.ContentType;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.measurement.dynamite.ModuleDescriptor;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.math.RoundingMode;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public abstract class Yo {
    public static HashMap d;
    public static final String a = Build.DEVICE + ", " + Build.MODEL + ", " + Build.MANUFACTURER + ", " + Build.VERSION.SDK_INT;
    public static final byte[] b = new byte[0];
    public static final Pattern c = Pattern.compile("(?:.*\\.)?isml?(?:/(manifest(.*))?)?", 2);
    public static final String[] e = {"alb", "sq", "arm", "hy", "baq", "eu", "bur", "my", "tib", "bo", "chi", "zh", "cze", "cs", "dut", "nl", "ger", "de", "gre", "el", "fre", "fr", "geo", "ka", "ice", "is", "mac", "mk", "mao", "mi", "may", "ms", "per", "fa", "rum", "ro", "scc", "hbs-srp", "slo", "sk", "wel", "cy", "id", "ms-ind", "iw", "he", "heb", "he", "ji", "yi", "arb", "ar-arb", "in", "ms-ind", "ind", "ms-ind", "nb", "no-nob", "nob", "no-nob", "nn", "no-nno", "nno", "no-nno", "tw", "ak-twi", "twi", "ak-twi", "bs", "hbs-bos", "bos", "hbs-bos", "hr", "hbs-hrv", "hrv", "hbs-hrv", "sr", "hbs-srp", "srp", "hbs-srp", "cmn", "zh-cmn", "hak", "zh-hak", "nan", "zh-nan", "hsn", "zh-hsn"};
    public static final String[] f = {"i-lux", "lb", "i-hak", "zh-hak", "i-navajo", "nv", "no-bok", "no-nob", "no-nyn", "no-nno", "zh-guoyu", "zh-cmn", "zh-hakka", "zh-hak", "zh-min-nan", "zh-nan", "zh-xiang", "zh-hsn"};
    public static final int[] g = {0, 79764919, 159529838, 222504665, 319059676, 398814059, 445009330, 507990021, 638119352, 583659535, 797628118, 726387553, 890018660, 835552979, 1015980042, 944750013, 1276238704, 1221641927, 1167319070, 1095957929, 1595256236, 1540665371, 1452775106, 1381403509, 1780037320, 1859660671, 1671105958, 1733955601, 2031960084, 2111593891, 1889500026, 1952343757, -1742489888, -1662866601, -1851683442, -1788833735, -1960329156, -1880695413, -2103051438, -2040207643, -1104454824, -1159051537, -1213636554, -1284997759, -1389417084, -1444007885, -1532160278, -1603531939, -734892656, -789352409, -575645954, -646886583, -952755380, -1007220997, -827056094, -898286187, -231047128, -151282273, -71779514, -8804623, -515967244, -436212925, -390279782, -327299027, 881225847, 809987520, 1023691545, 969234094, 662832811, 591600412, 771767749, 717299826, 311336399, 374308984, 453813921, 533576470, 25881363, 88864420, 134795389, 214552010, 2023205639, 2086057648, 1897238633, 1976864222, 1804852699, 1867694188, 1645340341, 1724971778, 1587496639, 1516133128, 1461550545, 1406951526, 1302016099, 1230646740, 1142491917, 1087903418, -1398421865, -1469785312, -1524105735, -1578704818, -1079922613, -1151291908, -1239184603, -1293773166, -1968362705, -1905510760, -2094067647, -2014441994, -1716953613, -1654112188, -1876203875, -1796572374, -525066777, -462094256, -382327159, -302564546, -206542021, -143559028, -97365931, -17609246, -960696225, -1031934488, -817968335, -872425850, -709327229, -780559564, -600130067, -654598054, 1762451694, 1842216281, 1619975040, 1682949687, 2047383090, 2127137669, 1938468188, 2001449195, 1325665622, 1271206113, 1183200824, 1111960463, 1543535498, 1489069629, 1434599652, 1363369299, 622672798, 568075817, 748617968, 677256519, 907627842, 853037301, 1067152940, 995781531, 51762726, 131386257, 177728840, 240578815, 269590778, 349224269, 429104020, 491947555, -248556018, -168932423, -122852000, -60002089, -500490030, -420856475, -341238852, -278395381, -685261898, -739858943, -559578920, -630940305, -1004286614, -1058877219, -845023740, -916395085, -1119974018, -1174433591, -1262701040, -1333941337, -1371866206, -1426332139, -1481064244, -1552294533, -1690935098, -1611170447, -1833673816, -1770699233, -2009983462, -1930228819, -2119160460, -2056179517, 1569362073, 1498123566, 1409854455, 1355396672, 1317987909, 1246755826, 1192025387, 1137557660, 2072149281, 2135122070, 1912620623, 1992383480, 1753615357, 1816598090, 1627664531, 1707420964, 295390185, 358241886, 404320391, 483945776, 43990325, 106832002, 186451547, 266083308, 932423249, 861060070, 1041341759, 986742920, 613929101, 542559546, 756411363, 701822548, -978770311, -1050133554, -869589737, -924188512, -693284699, -764654318, -550540341, -605129092, -475935807, -413084042, -366743377, -287118056, -257573603, -194731862, -114850189, -35218492, -1984365303, -1921392450, -2143631769, -2063868976, -1698919467, -1635936670, -1824608069, -1744851700, -1347415887, -1418654458, -1506661409, -1561119128, -1129027987, -1200260134, -1254728445, -1309196108};
    public static final int[] h = {0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935};
    public static final int[] i = {0, 7, 14, 9, 28, 27, 18, 21, 56, 63, 54, 49, 36, 35, 42, 45, ContentType.LONG_FORM_ON_DEMAND, 119, 126, ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 98, 101, 72, 79, 70, 65, 84, 83, 90, 93, 224, AdvertisementType.BRANDED_ON_DEMAND_PRE_ROLL, 238, AdvertisementType.BRANDED_ON_DEMAND_POST_ROLL, 252, 251, 242, 245, 216, 223, 214, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_MOVED_REGION, 196, 195, 202, 205, 144, 151, 158, 153, 140, 139, 130, 133, 168, 175, 166, 161, SubsamplingScaleImageView.ORIENTATION_180, 179, 186, 189, ContentType.BUMPER, 192, 201, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF, 219, 220, AdvertisementType.ON_DEMAND_POST_ROLL, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SHOW_PC_CALLED, 255, 248, 241, 246, 227, 228, 237, AdvertisementType.BRANDED_AS_CONTENT, 183, 176, 185, 190, 171, 172, 165, 162, 143, 136, 129, 134, 147, 148, 157, 154, 39, 32, 41, 46, 59, 60, 53, 50, 31, 24, 17, 22, 3, 4, 13, 10, 87, 80, 89, 94, 75, 76, 69, 66, 111, 104, 97, 102, 115, 116, 125, ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND, 137, 142, 135, 128, 149, 146, 155, 156, 177, 182, 191, 184, 173, 170, 163, 164, 249, 254, 247, 240, 229, 226, AdvertisementType.BRANDED_DURING_LIVE, 236, 193, 198, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SYNC_FAILED, 200, AdvertisementType.LIVE, 218, 211, AdvertisementType.ON_DEMAND_MID_ROLL, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED, 103, 96, 117, 114, ContentType.USER_GENERATED_LIVE, 124, 81, 86, 95, 88, 77, 74, 67, 68, 25, 30, 23, 16, 5, 2, 11, 12, 33, 38, 47, 40, 61, 58, 51, 52, 78, 73, 64, 71, 82, 85, 92, 91, 118, ContentType.LIVE, 120, 127, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION, 100, 99, 62, 57, 48, 55, 34, 37, 44, 43, 6, 1, 8, 15, 26, 29, 20, 19, 174, 169, 160, 167, 178, 181, 188, 187, 150, 145, 152, 159, 138, ModuleDescriptor.MODULE_VERSION, 132, 131, 222, com.google.android.gms.dynamite.descriptors.com.google.android.gms.tagmanager.ModuleDescriptor.MODULE_VERSION, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY, 215, 194, 197, 204, 203, 230, 225, AdvertisementType.BRANDED_ON_DEMAND_MID_ROLL, 239, 250, 253, 244, 243};

    public static String a(String str) throws MissingResourceException {
        if (str == null) {
            return null;
        }
        String strReplace = str.replace('_', '-');
        if (!strReplace.isEmpty() && !strReplace.equals("und")) {
            str = strReplace;
        }
        String strF = AbstractC2543qs.f(str);
        int i2 = 0;
        String str2 = strF.split("-", 2)[0];
        if (d == null) {
            String[] iSOLanguages = Locale.getISOLanguages();
            int length = iSOLanguages.length;
            String[] strArr = e;
            int length2 = strArr.length;
            HashMap map = new HashMap(length + 88);
            for (String str3 : iSOLanguages) {
                try {
                    String iSO3Language = new Locale(str3).getISO3Language();
                    if (!TextUtils.isEmpty(iSO3Language)) {
                        map.put(iSO3Language, str3);
                    }
                } catch (MissingResourceException unused) {
                }
            }
            for (int i3 = 0; i3 < 88; i3 += 2) {
                map.put(strArr[i3], strArr[i3 + 1]);
            }
            d = map;
        }
        String str4 = (String) d.get(str2);
        if (str4 != null) {
            strF = str4.concat(String.valueOf(strF.substring(str2.length())));
            str2 = str4;
        }
        if (!"no".equals(str2) && !"i".equals(str2) && !"zh".equals(str2)) {
            return strF;
        }
        while (true) {
            String[] strArr2 = f;
            int length3 = strArr2.length;
            if (i2 >= 18) {
                return strF;
            }
            if (strF.startsWith(strArr2[i2])) {
                return String.valueOf(strArr2[i2 + 1]).concat(String.valueOf(strF.substring(strArr2[i2].length())));
            }
            i2 += 2;
        }
    }

    public static void b(long[] jArr, long j) {
        long j2;
        RoundingMode roundingMode = RoundingMode.DOWN;
        int i2 = 0;
        if (j >= 1000000 && j % 1000000 == 0) {
            long jN = AbstractC2457os.n(j, 1000000L, RoundingMode.UNNECESSARY);
            while (i2 < jArr.length) {
                jArr[i2] = AbstractC2457os.n(jArr[i2], jN, roundingMode);
                i2++;
            }
            return;
        }
        if (j < 1000000 && 1000000 % j == 0) {
            long jN2 = AbstractC2457os.n(1000000L, j, RoundingMode.UNNECESSARY);
            while (i2 < jArr.length) {
                jArr[i2] = AbstractC2457os.v(jArr[i2], jN2);
                i2++;
            }
            return;
        }
        int i3 = 0;
        while (i3 < jArr.length) {
            long j3 = jArr[i3];
            if (j3 != 0) {
                if (j >= j3 && j % j3 == 0) {
                    jArr[i3] = AbstractC2457os.n(1000000L, AbstractC2457os.n(j, j3, RoundingMode.UNNECESSARY), roundingMode);
                } else if (j >= j3 || j3 % j != 0) {
                    j2 = j;
                    jArr[i3] = h(j3, 1000000L, j2, roundingMode);
                } else {
                    jArr[i3] = AbstractC2457os.v(1000000L, AbstractC2457os.n(j3, j, RoundingMode.UNNECESSARY));
                }
                j2 = j;
            } else {
                j2 = j;
            }
            i3++;
            j = j2;
        }
    }

    public static boolean c(int i2) {
        return i2 == 3 || i2 == 2 || i2 == 268435456 || i2 == 21 || i2 == 1342177280 || i2 == 22 || i2 == 1610612736 || i2 == 4;
    }

    public static boolean d(Context context) {
        int i2 = Build.VERSION.SDK_INT;
        if (i2 < 29 || context.getApplicationInfo().targetSdkVersion < 29) {
            return true;
        }
        if (i2 == 30) {
            String str = Build.MODEL;
            if (AbstractC2543qs.v("moto g(20)", str) || AbstractC2543qs.v("rmx3231", str)) {
                return true;
            }
        }
        return i2 == 34 && AbstractC2543qs.v("sm-x200", Build.MODEL);
    }

    public static boolean e(Context context) {
        UiModeManager uiModeManager = (UiModeManager) context.getApplicationContext().getSystemService("uimode");
        return uiModeManager != null && uiModeManager.getCurrentModeType() == 4;
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x004f, code lost:
    
        r5.i(r4);
        r4 = true;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean f(com.google.android.gms.internal.ads.Kn r4, com.google.android.gms.internal.ads.Kn r5, java.util.zip.Inflater r6) {
        /*
            int r0 = r4.s()
            r1 = 0
            if (r0 <= 0) goto L79
            byte[] r0 = r4.a
            int r2 = r4.b
            r0 = r0[r2]
            r0 = r0 & 255(0xff, float:3.57E-43)
            r2 = 120(0x78, float:1.68E-43)
            if (r0 != r2) goto L79
            int r0 = r4.s()
            r2 = 1
            if (r0 != 0) goto L1c
            r4 = r1
            goto L76
        L1c:
            byte[] r0 = r5.a
            int r0 = r0.length
            int r3 = r4.s()
            if (r0 >= r3) goto L2d
            int r0 = r4.s()
            int r0 = r0 + r0
            r5.e(r0)
        L2d:
            if (r6 != 0) goto L34
            java.util.zip.Inflater r6 = new java.util.zip.Inflater
            r6.<init>()
        L34:
            byte[] r0 = r4.a
            int r3 = r4.b
            int r4 = r4.s()
            r6.setInput(r0, r3, r4)
            r4 = r1
        L40:
            byte[] r0 = r5.a     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            int r3 = r0.length     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            int r3 = r3 - r4
            int r0 = r6.inflate(r0, r4, r3)     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            int r4 = r4 + r0
            boolean r0 = r6.finished()     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            if (r0 == 0) goto L56
            r5.i(r4)     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            r4 = r2
            goto L73
        L54:
            r4 = move-exception
            goto L6f
        L56:
            boolean r0 = r6.needsDictionary()     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            if (r0 != 0) goto L62
            boolean r0 = r6.needsInput()     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            if (r0 == 0) goto L64
        L62:
            r4 = r1
            goto L73
        L64:
            byte[] r0 = r5.a     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            int r3 = r0.length     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            if (r4 != r3) goto L40
            int r0 = r0.length     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            int r0 = r0 + r0
            r5.e(r0)     // Catch: java.lang.Throwable -> L54 java.util.zip.DataFormatException -> L62
            goto L40
        L6f:
            r6.reset()
            throw r4
        L73:
            r6.reset()
        L76:
            if (r4 == 0) goto L79
            return r2
        L79:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Yo.f(com.google.android.gms.internal.ads.Kn, com.google.android.gms.internal.ads.Kn, java.util.zip.Inflater):boolean");
    }

    public static Object[] g(int i2, Object[] objArr) {
        AbstractC1795We.B(i2 <= objArr.length);
        return Arrays.copyOf(objArr, i2);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00fe  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0100  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static long h(long r9, long r11, long r13, java.math.RoundingMode r15) {
        /*
            Method dump skipped, instructions count: 316
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Yo.h(long, long, long, java.math.RoundingMode):long");
    }

    public static String i(String str) throws ClassNotFoundException {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            return (String) cls.getMethod("get", String.class).invoke(cls, str);
        } catch (Exception e2) {
            AbstractC2096gb.A("Util", "Failed to read system property ".concat(str), e2);
            return null;
        }
    }

    public static int j(int[] iArr, int i2, boolean z, boolean z2) {
        int i3;
        int i4;
        int iBinarySearch = Arrays.binarySearch(iArr, i2);
        if (iBinarySearch < 0) {
            i4 = -(iBinarySearch + 2);
        } else {
            while (true) {
                i3 = iBinarySearch - 1;
                if (i3 < 0 || iArr[i3] != i2) {
                    break;
                }
                iBinarySearch = i3;
            }
            i4 = z ? iBinarySearch : i3;
        }
        return z2 ? Math.max(0, i4) : i4;
    }

    public static int k(long[] jArr, long j, boolean z) {
        int i2;
        int iBinarySearch = Arrays.binarySearch(jArr, j);
        if (iBinarySearch < 0) {
            i2 = -(iBinarySearch + 2);
        } else {
            while (true) {
                int i3 = iBinarySearch - 1;
                if (i3 < 0 || jArr[i3] != j) {
                    break;
                }
                iBinarySearch = i3;
            }
            i2 = iBinarySearch;
        }
        return z ? Math.max(0, i2) : i2;
    }

    public static int l(int i2, int i3, byte[] bArr, int i4) {
        while (i2 < i3) {
            i4 = g[(i4 >>> 24) ^ (bArr[i2] & 255)] ^ (i4 << 8);
            i2++;
        }
        return i4;
    }

    public static int m(int i2) {
        if (i2 == 20) {
            return 30;
        }
        if (i2 == 22) {
            return 31;
        }
        if (i2 == 30) {
            return 34;
        }
        switch (i2) {
            case 2:
            case 3:
                return 3;
            case 4:
            case 5:
            case 6:
                return 21;
            case 7:
            case 8:
                return 23;
            case 9:
            case 10:
            case 11:
            case 12:
                return 28;
            default:
                switch (i2) {
                    case 14:
                        return 25;
                    case 15:
                    case 16:
                    case 17:
                    case 18:
                        return 28;
                    default:
                        return SubsamplingScaleImageView.TILE_SIZE_AUTO;
                }
        }
    }

    public static int n(int i2) {
        int i3;
        int i4 = 6396;
        if (i2 == 10) {
            i3 = 737532;
        } else {
            if (i2 == 12) {
                return 743676;
            }
            if (i2 != 24) {
                switch (i2) {
                    case 1:
                        return 4;
                    case 2:
                        return 12;
                    case 3:
                        return 28;
                    case 4:
                        return 204;
                    case 5:
                        return 220;
                    case 6:
                        return 252;
                    case 7:
                        return 1276;
                    case 8:
                        return 6396;
                    default:
                        return 0;
                }
            }
            i3 = 67108860;
            i4 = 0;
        }
        return Build.VERSION.SDK_INT >= 32 ? i3 : i4;
    }

    public static int o(int i2) {
        if (i2 != 2) {
            if (i2 == 3) {
                return 1;
            }
            if (i2 != 4) {
                if (i2 != 21) {
                    if (i2 != 22) {
                        if (i2 != 268435456) {
                            if (i2 != 1342177280) {
                                if (i2 != 1610612736) {
                                    throw new IllegalArgumentException();
                                }
                            }
                        }
                    }
                }
                return 3;
            }
            return 4;
        }
        return 2;
    }

    public static int p(int i2) {
        if (i2 == 2 || i2 == 4) {
            return 6005;
        }
        if (i2 == 10) {
            return 6004;
        }
        if (i2 == 7) {
            return 6005;
        }
        if (i2 == 8) {
            return 6003;
        }
        switch (i2) {
            case 15:
                return 6003;
            case 16:
            case 18:
                return 6005;
            case 17:
            case 19:
            case 20:
            case 21:
            case EventType.WINDOW_STATE /* 22 */:
                return 6004;
            default:
                switch (i2) {
                    case EventType.VIDEO /* 24 */:
                    case EventType.SUBS /* 25 */:
                    case EventType.CDN /* 26 */:
                    case 27:
                    case 28:
                        return 6002;
                    default:
                        return 6006;
                }
        }
    }

    public static int q(String str) throws NumberFormatException {
        String[] strArrSplit;
        int length;
        if (str == null || (length = (strArrSplit = str.split("_", -1)).length) < 2) {
            return 0;
        }
        String str2 = strArrSplit[length - 1];
        boolean z = length >= 3 && "neg".equals(strArrSplit[length + (-2)]);
        try {
            if (str2 == null) {
                throw null;
            }
            int i2 = Integer.parseInt(str2);
            return z ? -i2 : i2;
        } catch (NumberFormatException unused) {
            return 0;
        }
    }

    public static int r(int i2) {
        if (i2 == 8) {
            return 3;
        }
        if (i2 == 16) {
            return 2;
        }
        if (i2 != 24) {
            return i2 != 32 ? 0 : 22;
        }
        return 21;
    }

    public static long s(long j, float f2) {
        return f2 == 1.0f ? j : Math.round(j * f2);
    }

    public static long t(long j) {
        return (j == -9223372036854775807L || j == Long.MIN_VALUE) ? j : j * 1000;
    }

    public static long u(int i2, long j) {
        return v(j, 1000000L, i2, RoundingMode.DOWN);
    }

    public static long v(long j, long j2, long j3, RoundingMode roundingMode) {
        if (j == 0 || j2 == 0) {
            return 0L;
        }
        return (j3 < j2 || j3 % j2 != 0) ? (j3 >= j2 || j2 % j3 != 0) ? (j3 < j || j3 % j != 0) ? (j3 >= j || j % j3 != 0) ? h(j, j2, j3, roundingMode) : AbstractC2457os.v(j2, AbstractC2457os.n(j, j3, RoundingMode.UNNECESSARY)) : AbstractC2457os.n(j2, AbstractC2457os.n(j3, j, RoundingMode.UNNECESSARY), roundingMode) : AbstractC2457os.v(j, AbstractC2457os.n(j2, j3, RoundingMode.UNNECESSARY)) : AbstractC2457os.n(j, AbstractC2457os.n(j3, j2, RoundingMode.UNNECESSARY), roundingMode);
    }

    public static long w(long j) {
        return (j == -9223372036854775807L || j == Long.MIN_VALUE) ? j : j / 1000;
    }
}
