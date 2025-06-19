package com.appsflyer.internal;

import android.text.TextUtils;
import android.view.ViewConfiguration;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DtbConstants;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/* loaded from: classes.dex */
public final class AFf1pSDK {
    private static int $10 = 0;
    private static int $11 = 1;
    private static int AFAdRevenueData = 0;
    private static int getCurrencyIso4217Code = 1;
    private static int[] getMediationNetwork;

    static {
        getMediationNetwork();
        ViewConfiguration.getLongPressTimeout();
        int i = getCurrencyIso4217Code + 3;
        AFAdRevenueData = i % 128;
        if (i % 2 != 0) {
            int i2 = 75 / 0;
        }
    }

    private static String AFAdRevenueData(String str, String str2, String str3, String str4, String str5) throws NoSuchAlgorithmException, InvalidKeyException {
        String revenue;
        int i = AFAdRevenueData + 85;
        getCurrencyIso4217Code = i % 128;
        if (i % 2 == 0) {
            String[] strArr = new String[2];
            strArr[0] = str2;
            strArr[1] = str3;
            strArr[5] = str4;
            strArr[5] = str5;
            strArr[4] = "";
            revenue = AFj1cSDK.getRevenue(TextUtils.join("\u2063", strArr), str);
            if (revenue.length() < 63) {
                return revenue;
            }
        } else {
            revenue = AFj1cSDK.getRevenue(TextUtils.join("\u2063", new String[]{str2, str3, str4, str5, ""}), str);
            if (revenue.length() < 12) {
                return revenue;
            }
        }
        String strSubstring = revenue.substring(0, 12);
        int i2 = AFAdRevenueData + 47;
        getCurrencyIso4217Code = i2 % 128;
        if (i2 % 2 != 0) {
            return strSubstring;
        }
        throw null;
    }

    private static void a(int[] iArr, int i, Object[] objArr) {
        AFk1kSDK aFk1kSDK = new AFk1kSDK();
        char[] cArr = new char[4];
        char[] cArr2 = new char[iArr.length * 2];
        int[] iArr2 = getMediationNetwork;
        if (iArr2 != null) {
            int length = iArr2.length;
            int[] iArr3 = new int[length];
            $10 = ($11 + 59) % 128;
            int i2 = 0;
            while (i2 < length) {
                int i3 = $10 + 39;
                $11 = i3 % 128;
                if (i3 % 2 == 0) {
                    iArr3[i2] = (int) (iArr2[i2] * 3670241895213185600L);
                    i2 %= 1;
                } else {
                    iArr3[i2] = (int) (iArr2[i2] ^ 3670241895213185600L);
                    i2++;
                }
            }
            iArr2 = iArr3;
        }
        int length2 = iArr2.length;
        int[] iArr4 = new int[length2];
        int[] iArr5 = getMediationNetwork;
        if (iArr5 != null) {
            int length3 = iArr5.length;
            int[] iArr6 = new int[length3];
            for (int i4 = 0; i4 < length3; i4++) {
                $11 = ($10 + 79) % 128;
                iArr6[i4] = (int) (iArr5[i4] ^ 3670241895213185600L);
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
            $11 = ($10 + 51) % 128;
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
                $10 = ($11 + 9) % 128;
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

    @NonNull
    private static AFi1uSDK getMediationNetwork(@NonNull AFi1wSDK aFi1wSDK, String str, @NonNull String str2, @NonNull String str3) {
        String string;
        if (str == null) {
            return new AFi1uSDK(aFi1wSDK.AFAdRevenueData == AFh1aSDK.DEFAULT, AFi1ySDK.NA);
        }
        Object[] objArr = new Object[1];
        a(new int[]{-643013363, -1773125790, -901337036, 656549561, -1731661770, 1258424067, -1532942264, 934407696, -1450123275, -1059473533, 82834636, 73705576, -1221507016, 1763733418, -1711569501, 1840946075, -1493249449, -1523654642, 594617170, -836811800, 1195240337, 1166309858, 1004762227, 96245697, 395058159, 64877192, 56299164, -104828535, -4786395, 2101942765, -285338731, 1554123850}, (ViewConfiguration.getDoubleTapTimeout() >> 16) + 64, objArr);
        String strIntern = ((String) objArr[0]).intern();
        if (aFi1wSDK.AFAdRevenueData == AFh1aSDK.CUSTOM) {
            string = new StringBuilder(str2).reverse().toString();
        } else {
            string = "";
            str3 = strIntern;
        }
        boolean zEquals = AFAdRevenueData(new StringBuilder(str3).reverse().toString(), aFi1wSDK.getCurrencyIso4217Code, DtbConstants.NATIVE_OS_NAME, "v1", string).equals(str);
        return new AFi1uSDK(zEquals, zEquals ? AFi1ySDK.SUCCESS : AFi1ySDK.FAILURE);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0017  */
    @androidx.annotation.NonNull
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.appsflyer.internal.AFi1uSDK getRevenue(@androidx.annotation.NonNull com.appsflyer.internal.AFi1wSDK r5, java.lang.String r6, @androidx.annotation.NonNull java.lang.String r7, @androidx.annotation.NonNull java.lang.String r8) {
        /*
            r4 = this;
            r0 = 0
            if (r5 == 0) goto L33
            int r1 = com.appsflyer.internal.AFf1pSDK.AFAdRevenueData
            int r2 = r1 + 29
            int r3 = r2 % 128
            com.appsflyer.internal.AFf1pSDK.getCurrencyIso4217Code = r3
            int r2 = r2 % 2
            if (r2 != 0) goto L15
            r2 = 9
            int r2 = r2 / r0
            if (r7 == 0) goto L33
            goto L17
        L15:
            if (r7 == 0) goto L33
        L17:
            if (r8 == 0) goto L33
            int r1 = r1 + 67
            int r1 = r1 % 128
            com.appsflyer.internal.AFf1pSDK.getCurrencyIso4217Code = r1
            com.appsflyer.internal.AFi1uSDK r5 = getMediationNetwork(r5, r6, r7, r8)
            int r6 = com.appsflyer.internal.AFf1pSDK.getCurrencyIso4217Code
            int r6 = r6 + 51
            int r7 = r6 % 128
            com.appsflyer.internal.AFf1pSDK.AFAdRevenueData = r7
            int r6 = r6 % 2
            if (r6 == 0) goto L32
            r6 = 27
            int r6 = r6 / r0
        L32:
            return r5
        L33:
            int r5 = com.appsflyer.internal.AFf1pSDK.AFAdRevenueData
            int r5 = r5 + 21
            int r5 = r5 % 128
            com.appsflyer.internal.AFf1pSDK.getCurrencyIso4217Code = r5
            com.appsflyer.internal.AFi1uSDK r5 = new com.appsflyer.internal.AFi1uSDK
            com.appsflyer.internal.AFi1ySDK r6 = com.appsflyer.internal.AFi1ySDK.INTERNAL_ERROR
            r5.<init>(r0, r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFf1pSDK.getRevenue(com.appsflyer.internal.AFi1wSDK, java.lang.String, java.lang.String, java.lang.String):com.appsflyer.internal.AFi1uSDK");
    }

    public static void getMediationNetwork() {
        getMediationNetwork = new int[]{-1667361725, -1699441632, 432593808, 251732126, -1427520749, -699397331, 585070146, 1483439762, 1609066215, 453290560, -192666392, -1278453714, -213940739, 2102241028, -1309214613, 1294459639, 1092066826, -1216170440};
    }
}
