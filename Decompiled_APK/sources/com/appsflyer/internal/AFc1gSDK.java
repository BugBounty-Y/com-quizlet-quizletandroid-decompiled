package com.appsflyer.internal;

import android.content.Context;
import android.graphics.Color;
import android.media.AudioTrack;
import android.os.Build;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.widget.ExpandableListView;
import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public final class AFc1gSDK extends HashMap<String, Object> {
    private static int $10 = 0;
    private static int $11 = 1;
    private static long AFAdRevenueData = 0;
    private static int areAllFieldsValid = 1;
    private static int[] getCurrencyIso4217Code;
    private static int getMonetizationNetwork;
    private final Map<String, Object> getMediationNetwork;
    private final Context getRevenue;

    public static class AFa1vSDK {
        public static byte[] getMediationNetwork(@NonNull byte[] bArr) throws Exception {
            for (int i = 0; i < bArr.length; i++) {
                bArr[i] = (byte) (bArr[i] ^ ((i % 2) + 42));
            }
            return bArr;
        }

        @NonNull
        public static byte[] getMonetizationNetwork(@NonNull String str) throws Exception {
            return str.getBytes(Charset.defaultCharset());
        }
    }

    static {
        getMediationNetwork();
        TextUtils.indexOf("", "");
        KeyEvent.getModifierMetaStateMask();
        ViewConfiguration.getScrollDefaultDelay();
        SystemClock.currentThreadTimeMillis();
        KeyEvent.getDeadChar(0, 0);
        ViewConfiguration.getTapTimeout();
        ExpandableListView.getPackedPositionForGroup(0);
        int i = getMonetizationNetwork + 5;
        areAllFieldsValid = i % 128;
        if (i % 2 == 0) {
            throw null;
        }
    }

    public AFc1gSDK(Map<String, Object> map, Context context) {
        this.getMediationNetwork = map;
        this.getRevenue = context;
        put(getMonetizationNetwork(), getCurrencyIso4217Code());
    }

    private static void a(String str, int i, Object[] objArr) {
        int i2 = $10 + 21;
        $11 = i2 % 128;
        char[] charArray = str;
        if (i2 % 2 == 0) {
            throw null;
        }
        if (str != null) {
            charArray = str.toCharArray();
        }
        char[] cArr = charArray;
        AFk1pSDK aFk1pSDK = new AFk1pSDK();
        aFk1pSDK.getMediationNetwork = i;
        int length = cArr.length;
        long[] jArr = new long[length];
        aFk1pSDK.getRevenue = 0;
        while (true) {
            int i3 = aFk1pSDK.getRevenue;
            if (i3 >= cArr.length) {
                break;
            }
            jArr[i3] = (cArr[i3] ^ (i3 * aFk1pSDK.getMediationNetwork)) ^ (AFAdRevenueData ^ 199061409475100049L);
            aFk1pSDK.getRevenue = i3 + 1;
        }
        char[] cArr2 = new char[length];
        aFk1pSDK.getRevenue = 0;
        while (true) {
            int i4 = aFk1pSDK.getRevenue;
            if (i4 >= cArr.length) {
                objArr[0] = new String(cArr2);
                return;
            }
            int i5 = $11 + 97;
            int i6 = i5 % 128;
            $10 = i6;
            if (i5 % 2 != 0) {
                cArr2[i4] = (char) jArr[i4];
            } else {
                cArr2[i4] = (char) jArr[i4];
                i4++;
            }
            aFk1pSDK.getRevenue = i4;
            $11 = (i6 + 95) % 128;
        }
    }

    private static void b(int[] iArr, int i, Object[] objArr) {
        AFk1kSDK aFk1kSDK = new AFk1kSDK();
        char[] cArr = new char[4];
        char[] cArr2 = new char[iArr.length * 2];
        int[] iArr2 = getCurrencyIso4217Code;
        if (iArr2 != null) {
            $11 = ($10 + 61) % 128;
            int length = iArr2.length;
            int[] iArr3 = new int[length];
            for (int i2 = 0; i2 < length; i2++) {
                iArr3[i2] = (int) (iArr2[i2] ^ 3670241895213185600L);
            }
            iArr2 = iArr3;
        }
        int length2 = iArr2.length;
        int[] iArr4 = new int[length2];
        int[] iArr5 = getCurrencyIso4217Code;
        if (iArr5 != null) {
            int length3 = iArr5.length;
            int[] iArr6 = new int[length3];
            int i3 = 0;
            while (i3 < length3) {
                int i4 = $11 + 57;
                $10 = i4 % 128;
                if (i4 % 2 != 0) {
                    iArr6[i3] = (int) (iArr5[i3] / 3670241895213185600L);
                    i3 >>= 1;
                } else {
                    iArr6[i3] = (int) (iArr5[i3] ^ 3670241895213185600L);
                    i3++;
                }
            }
            iArr5 = iArr6;
        }
        System.arraycopy(iArr5, 0, iArr4, 0, length2);
        aFk1kSDK.getCurrencyIso4217Code = 0;
        while (true) {
            int i5 = aFk1kSDK.getCurrencyIso4217Code;
            if (i5 >= iArr.length) {
                objArr[0] = new String(cArr2, 0, i);
                return;
            }
            int i6 = iArr[i5];
            char c = (char) (i6 >> 16);
            cArr[0] = c;
            char c2 = (char) i6;
            cArr[1] = c2;
            char c3 = (char) (iArr[i5 + 1] >> 16);
            cArr[2] = c3;
            char c4 = (char) iArr[i5 + 1];
            cArr[3] = c4;
            aFk1kSDK.AFAdRevenueData = (c << 16) + c2;
            aFk1kSDK.getMonetizationNetwork = (c3 << 16) + c4;
            AFk1kSDK.getMediationNetwork(iArr4);
            for (int i7 = 0; i7 < 16; i7++) {
                int i8 = aFk1kSDK.AFAdRevenueData ^ iArr4[i7];
                aFk1kSDK.AFAdRevenueData = i8;
                int iAFAdRevenueData = AFk1kSDK.AFAdRevenueData(i8) ^ aFk1kSDK.getMonetizationNetwork;
                int i9 = aFk1kSDK.AFAdRevenueData;
                aFk1kSDK.AFAdRevenueData = iAFAdRevenueData;
                aFk1kSDK.getMonetizationNetwork = i9;
            }
            int i10 = aFk1kSDK.AFAdRevenueData;
            int i11 = aFk1kSDK.getMonetizationNetwork;
            aFk1kSDK.AFAdRevenueData = i11;
            aFk1kSDK.getMonetizationNetwork = i10;
            int i12 = i10 ^ iArr4[16];
            aFk1kSDK.getMonetizationNetwork = i12;
            int i13 = i11 ^ iArr4[17];
            aFk1kSDK.AFAdRevenueData = i13;
            cArr[0] = (char) (i13 >>> 16);
            cArr[1] = (char) i13;
            cArr[2] = (char) (i12 >>> 16);
            cArr[3] = (char) i12;
            AFk1kSDK.getMediationNetwork(iArr4);
            int i14 = aFk1kSDK.getCurrencyIso4217Code;
            cArr2[i14 * 2] = cArr[0];
            cArr2[(i14 * 2) + 1] = cArr[1];
            cArr2[(i14 * 2) + 2] = cArr[2];
            cArr2[(i14 * 2) + 3] = cArr[3];
            aFk1kSDK.getCurrencyIso4217Code = i14 + 2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x01a5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private java.lang.String getCurrencyIso4217Code() {
        /*
            Method dump skipped, instructions count: 1052
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFc1gSDK.getCurrencyIso4217Code():java.lang.String");
    }

    private static StringBuilder getMediationNetwork(@NonNull String... strArr) throws Exception {
        ArrayList arrayList = new ArrayList();
        int length = strArr.length;
        for (int i = 0; i < 3; i++) {
            arrayList.add(Integer.valueOf(strArr[i].length()));
        }
        Collections.sort(arrayList);
        int iIntValue = ((Integer) arrayList.get(0)).intValue();
        StringBuilder sb = new StringBuilder();
        for (int i2 = 0; i2 < iIntValue; i2++) {
            getMonetizationNetwork = (areAllFieldsValid + 47) % 128;
            Integer numValueOf = null;
            for (int i3 = 0; i3 < 3; i3++) {
                int iCharAt = strArr[i3].charAt(i2);
                if (numValueOf != null) {
                    iCharAt ^= numValueOf.intValue();
                }
                numValueOf = Integer.valueOf(iCharAt);
            }
            sb.append(Integer.toHexString(numValueOf.intValue()));
        }
        return sb;
    }

    @NonNull
    private String getMonetizationNetwork() {
        getMonetizationNetwork = (areAllFieldsValid + 3) % 128;
        try {
            String string = Integer.toString(Build.VERSION.SDK_INT);
            Map<String, Object> map = this.getMediationNetwork;
            Object[] objArr = new Object[1];
            a("ٓ䛅蝏쟵П䒊蔱얶ˎ䍊菵쁹", 16530 - (AudioTrack.getMaxVolume() > DefinitionKt.NO_Float_VALUE ? 1 : (AudioTrack.getMaxVolume() == DefinitionKt.NO_Float_VALUE ? 0 : -1)), objArr);
            String string2 = map.get(((String) objArr[0]).intern()).toString();
            Map<String, Object> map2 = this.getMediationNetwork;
            Object[] objArr2 = new Object[1];
            a("ِ彗둽ങ戊", View.getDefaultSize(0, 0) + 22807, objArr2);
            String string3 = map2.get(((String) objArr2[0]).intern()).toString();
            if (string3 == null) {
                areAllFieldsValid = (getMonetizationNetwork + 29) % 128;
                Object[] objArr3 = new Object[1];
                a("ټ\u0cd4ጿᦋⳄ㌾㦊䳩", 2729 - View.MeasureSpec.getSize(0), objArr3);
                string3 = ((String) objArr3[0]).intern();
            }
            StringBuilder sb = new StringBuilder(string2);
            sb.reverse();
            StringBuilder mediationNetwork = getMediationNetwork(string, string3, sb.toString());
            int length = mediationNetwork.length();
            if (length > 4) {
                mediationNetwork.delete(4, length);
            } else {
                while (length < 4) {
                    length++;
                    mediationNetwork.append('1');
                }
            }
            Object[] objArr4 = new Object[1];
            b(new int[]{-269708407, 691550562}, Color.green(0) + 3, objArr4);
            mediationNetwork.insert(0, ((String) objArr4[0]).intern());
            return mediationNetwork.toString();
        } catch (Exception e) {
            Object[] objArr5 = new Object[1];
            b(new int[]{854565745, 306981016, 2092009709, 1211146027, -1997348285, -2069302082, -1014555636, -1115818356, 1491143540, 297822326, -891867092, 74755836, -538226225, -689317204, -1794805564, -1830683349, -1867036264, 1235626699, 1541426602, 1401202182}, 40 - Color.argb(0, 0, 0, 0), objArr5);
            AFLogger.afErrorLogForExcManagerOnly(((String) objArr5[0]).intern(), e);
            StringBuilder sb2 = new StringBuilder();
            Object[] objArr6 = new Object[1];
            b(new int[]{-1080009004, 844403482, -683446169, 2011701581, 1233271862, -317730360, 474044529, -1279916753, -2006198622, 428775418, 1632684225, -344979390, -1051640727, -1500483547, 1921909678, 1197372451, 1709650531, 1369506269, 1275252993, 1437497808, 761424572, -1240279331}, 42 - (KeyEvent.getMaxKeyCode() >> 16), objArr6);
            sb2.append(((String) objArr6[0]).intern());
            sb2.append(e);
            AFLogger.afRDLog(sb2.toString());
            Object[] objArr7 = new Object[1];
            b(new int[]{-2132896634, 840027810, -513331929, 1353535124}, (ExpandableListView.getPackedPositionForChild(0, 0) > 0L ? 1 : (ExpandableListView.getPackedPositionForChild(0, 0) == 0L ? 0 : -1)) + 8, objArr7);
            return ((String) objArr7[0]).intern();
        }
    }

    public static void getMediationNetwork() {
        AFAdRevenueData = -8351283963653293149L;
        getCurrencyIso4217Code = new int[]{442543737, -1490671600, 624544975, 963078580, -38548639, -1507093695, -433807488, 2027768116, 1333435861, -1679971940, -735591064, 871109200, 1542131051, 1882103064, 1923897460, -2041115963, 1803608463, -148454374};
    }
}
