package com.appsflyer.internal;

import android.content.Context;
import android.content.pm.PackageManager;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.appsflyer.AppsFlyerProperties;
import com.comscore.streaming.ContentType;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/* loaded from: classes.dex */
public final class AFd1kSDK implements AFd1pSDK {
    private static int $10 = 0;
    private static int $11 = 1;
    private static long areAllFieldsValid = 0;
    private static char copy = 0;
    private static int equals = 1;
    private static final int getRevenue;
    private static int hashCode;
    private static int toString;
    private final AFc1dSDK component1;
    private List<String> getCurrencyIso4217Code = new ArrayList();
    private boolean getMonetizationNetwork = true;

    @NonNull
    private final Map<String, Object> AFAdRevenueData = new HashMap();
    private SecureRandom component3 = new SecureRandom();
    private boolean component2 = true ^ AppsFlyerProperties.getInstance().getBoolean(AppsFlyerProperties.DPM, false);
    private int getMediationNetwork = 0;
    private boolean component4 = false;

    static {
        component3();
        getRevenue = 98166;
        int i = equals + 117;
        toString = i % 128;
        if (i % 2 != 0) {
            int i2 = 69 / 0;
        }
    }

    public AFd1kSDK(AFc1dSDK aFc1dSDK) {
        this.component1 = aFc1dSDK;
    }

    private void AFInAppEventParameterName() {
        toString = (equals + 89) % 128;
        this.component1.component2().getMonetizationNetwork("participantInProxy");
        equals = (toString + ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND) % 128;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private static void a(int i, char c, String str, String str2, String str3, Object[] objArr) {
        char[] charArray;
        char[] charArray2;
        if (str3 != null) {
            int i2 = $11 + 31;
            $10 = i2 % 128;
            if (i2 % 2 != 0) {
                str3.toCharArray();
                throw null;
            }
            charArray = str3.toCharArray();
        } else {
            charArray = str3;
        }
        char[] cArr = charArray;
        if (str2 != 0) {
            charArray2 = str2.toCharArray();
            $10 = ($11 + 29) % 128;
        } else {
            charArray2 = str2;
        }
        char[] cArr2 = charArray2;
        char[] charArray3 = str != null ? str.toCharArray() : str;
        AFk1jSDK aFk1jSDK = new AFk1jSDK();
        int length = charArray3.length;
        char[] cArr3 = new char[length];
        int length2 = cArr.length;
        char[] cArr4 = new char[length2];
        System.arraycopy(charArray3, 0, cArr3, 0, length);
        System.arraycopy(cArr, 0, cArr4, 0, length2);
        cArr3[0] = (char) (cArr3[0] ^ c);
        cArr4[2] = (char) (cArr4[2] + ((char) i));
        int length3 = cArr2.length;
        char[] cArr5 = new char[length3];
        aFk1jSDK.getMediationNetwork = 0;
        while (true) {
            int i3 = aFk1jSDK.getMediationNetwork;
            if (i3 >= length3) {
                objArr[0] = new String(cArr5);
                return;
            }
            int i4 = (i3 + 3) % 4;
            int i5 = cArr3[i3 % 4] * 32718;
            char c2 = cArr4[(i3 + 2) % 4];
            char c3 = (char) ((i5 + c2) % 65535);
            aFk1jSDK.AFAdRevenueData = c3;
            cArr4[i4] = (char) (((cArr3[i4] * 32718) + c2) / 65535);
            cArr3[i4] = c3;
            cArr5[i3] = (char) ((((cArr2[i3] ^ c3) ^ (areAllFieldsValid ^ (-866183138771165766L))) ^ ((int) (hashCode ^ (-866183138771165766L)))) ^ ((char) (copy ^ (-866183138771165766L))));
            aFk1jSDK.getMediationNetwork = i3 + 1;
        }
    }

    private synchronized void areAllFieldsValid() {
        int i = toString + 63;
        equals = i % 128;
        if (i % 2 == 0) {
            throw null;
        }
        if (this.component4) {
            return;
        }
        this.component4 = true;
        try {
            getCurrencyIso4217Code("r_debugging_on", new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ", Locale.ENGLISH).format(Long.valueOf(System.currentTimeMillis())), new String[0]);
            equals = (toString + 3) % 128;
            return;
        } catch (Throwable th) {
            AFLogger.INSTANCE.e(AFg1cSDK.PROXY, "Error while starting remote debugger", th, true, true, true);
            return;
        }
    }

    private static String component1() {
        int i = toString;
        int i2 = i + 77;
        equals = i2 % 128;
        if (i2 % 2 == 0) {
            throw null;
        }
        equals = (i + 33) % 128;
        return "6.17.0";
    }

    private float component2() {
        equals = (toString + 65) % 128;
        float fNextFloat = this.component3.nextFloat();
        int i = equals + 119;
        toString = i % 128;
        if (i % 2 != 0) {
            int i2 = 16 / 0;
        }
        return fNextFloat;
    }

    public static void component3() {
        areAllFieldsValid = -866183138771165766L;
        hashCode = 1193057722;
        copy = (char) 29794;
    }

    @NonNull
    private synchronized Map<String, Object> copy() {
        Map<String, Object> map;
        equals = (toString + 47) % 128;
        this.AFAdRevenueData.put("data", this.getCurrencyIso4217Code);
        equals();
        map = this.AFAdRevenueData;
        toString = (equals + 111) % 128;
        return map;
    }

    private boolean copydefault() {
        return ((Boolean) getMediationNetwork(new Object[]{this}, -1999031441, 1999031443, System.identityHashCode(this))).booleanValue();
    }

    private synchronized void equals() {
        this.getCurrencyIso4217Code = new ArrayList();
        this.getMediationNetwork = 0;
        toString = (equals + 115) % 128;
    }

    public static /* synthetic */ Object getMediationNetwork(Object[] objArr, int i, int i2, int i3) {
        int i4 = ~i;
        int i5 = ~i2;
        int i6 = ~(i4 | i5);
        int i7 = ~i3;
        int i8 = (~(i4 | i7)) | i6 | (~(i5 | i7));
        int i9 = i | i2;
        int i10 = ((i8 | (~(i9 | i3))) * (-84)) + (i2 * 85) + (i * 85);
        int i11 = i | (~(i3 | i5));
        int i12 = ~(i2 | i7);
        int i13 = ((i12 | (~i9)) * 84) + ((i11 | i12) * (-84)) + i10;
        if (i13 == 1) {
            AFd1kSDK aFd1kSDK = (AFd1kSDK) objArr[0];
            String str = (String) objArr[1];
            String[] strArr = (String[]) objArr[2];
            equals = (toString + 69) % 128;
            aFd1kSDK.getCurrencyIso4217Code("public_api_call", str, strArr);
            toString = (equals + 1) % 128;
            return null;
        }
        if (i13 == 2) {
            return getCurrencyIso4217Code(objArr);
        }
        if (i13 == 3) {
            return getMonetizationNetwork(objArr);
        }
        AFd1kSDK aFd1kSDK2 = (AFd1kSDK) objArr[0];
        boolean zAFAdRevenueData = aFd1kSDK2.AFAdRevenueData(getCurrencyIso4217Code(aFd1kSDK2.component1.component1().getMediationNetwork.getCurrencyIso4217Code), getCurrencyIso4217Code(aFd1kSDK2.component1.component1().getMediationNetwork.AFAdRevenueData));
        if (!zAFAdRevenueData) {
            aFd1kSDK2.getRevenue();
            aFd1kSDK2.getMediationNetwork();
        } else {
            equals = (toString + 57) % 128;
            aFd1kSDK2.areAllFieldsValid();
        }
        equals = (toString + 31) % 128;
        return Boolean.valueOf(zAFAdRevenueData);
    }

    private Map<String, Object> p_(String str, PackageManager packageManager) {
        int i = equals + 95;
        toString = i % 128;
        if (i % 2 != 0) {
            q_(str, packageManager, this.component1.registerClient(), this.component1.afInfoLog());
            copy();
            throw null;
        }
        q_(str, packageManager, this.component1.registerClient(), this.component1.afInfoLog());
        Map<String, Object> mapCopy = copy();
        int i2 = equals + 29;
        toString = i2 % 128;
        if (i2 % 2 == 0) {
            return mapCopy;
        }
        throw null;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x004a A[Catch: all -> 0x0027, PHI: r1
  0x004a: PHI (r1v4 com.appsflyer.AppsFlyerProperties) = (r1v3 com.appsflyer.AppsFlyerProperties), (r1v5 com.appsflyer.AppsFlyerProperties) binds: [B:16:0x0039, B:9:0x0022] A[DONT_GENERATE, DONT_INLINE], TRY_ENTER, TRY_LEAVE, TryCatch #2 {all -> 0x0027, blocks: (B:4:0x0003, B:6:0x0010, B:19:0x004a, B:21:0x00a5, B:22:0x00bb, B:12:0x0026, B:15:0x002a, B:8:0x0021), top: B:33:0x0003, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x003b A[EXC_TOP_SPLITTER, PHI: r3
  0x003b: PHI (r3v2 java.lang.String) = (r3v1 java.lang.String), (r3v9 java.lang.String) binds: [B:16:0x0039, B:9:0x0022] A[DONT_GENERATE, DONT_INLINE], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private synchronized void q_(java.lang.String r6, android.content.pm.PackageManager r7, com.appsflyer.internal.AFf1gSDK r8, com.appsflyer.internal.AFc1kSDK r9) {
        /*
            r5 = this;
            java.lang.String r0 = "remote_debug_static_data"
            monitor-enter(r5)
            int r1 = com.appsflyer.internal.AFd1kSDK.toString     // Catch: java.lang.Throwable -> L27
            int r1 = r1 + 43
            int r2 = r1 % 128
            com.appsflyer.internal.AFd1kSDK.equals = r2     // Catch: java.lang.Throwable -> L27
            int r1 = r1 % 2
            r2 = 0
            if (r1 != 0) goto L2a
            com.appsflyer.AppsFlyerProperties r1 = com.appsflyer.AppsFlyerProperties.getInstance()     // Catch: java.lang.Throwable -> L27
            java.lang.String r3 = "remote_debug_static_data"
            java.lang.String r3 = r1.getString(r3)     // Catch: java.lang.Throwable -> L27
            java.util.Map<java.lang.String, java.lang.Object> r4 = r5.AFAdRevenueData     // Catch: java.lang.Throwable -> L27
            r4.clear()     // Catch: java.lang.Throwable -> L27
            r4 = 38
            int r4 = r4 / r2
            if (r3 == 0) goto L4a
            goto L3b
        L25:
            r6 = move-exception
            throw r6     // Catch: java.lang.Throwable -> L27
        L27:
            r6 = move-exception
            goto Ld6
        L2a:
            com.appsflyer.AppsFlyerProperties r1 = com.appsflyer.AppsFlyerProperties.getInstance()     // Catch: java.lang.Throwable -> L27
            java.lang.String r3 = "remote_debug_static_data"
            java.lang.String r3 = r1.getString(r3)     // Catch: java.lang.Throwable -> L27
            java.util.Map<java.lang.String, java.lang.Object> r4 = r5.AFAdRevenueData     // Catch: java.lang.Throwable -> L27
            r4.clear()     // Catch: java.lang.Throwable -> L27
            if (r3 == 0) goto L4a
        L3b:
            java.util.Map<java.lang.String, java.lang.Object> r6 = r5.AFAdRevenueData     // Catch: java.lang.Throwable -> Lbb
            org.json.JSONObject r7 = new org.json.JSONObject     // Catch: java.lang.Throwable -> Lbb
            r7.<init>(r3)     // Catch: java.lang.Throwable -> Lbb
            java.util.Map r7 = com.appsflyer.internal.AFg1lSDK.getMonetizationNetwork(r7)     // Catch: java.lang.Throwable -> Lbb
            r6.putAll(r7)     // Catch: java.lang.Throwable -> Lbb
            goto Lbb
        L4a:
            com.appsflyer.internal.AFc1dSDK r3 = r5.component1     // Catch: java.lang.Throwable -> L27
            com.appsflyer.internal.AFc1pSDK r3 = r3.getRevenue()     // Catch: java.lang.Throwable -> L27
            java.lang.String r3 = r3.AFAdRevenueData()     // Catch: java.lang.Throwable -> L27
            java.lang.String r8 = r8.getRevenue()     // Catch: java.lang.Throwable -> L27
            java.lang.String r9 = r9.AFAdRevenueData     // Catch: java.lang.Throwable -> L27
            r5.getMediationNetwork(r3, r8, r9)     // Catch: java.lang.Throwable -> L27
            java.lang.StringBuilder r8 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L27
            java.lang.String r9 = "6.17.0."
            r8.<init>(r9)     // Catch: java.lang.Throwable -> L27
            java.lang.String r9 = com.appsflyer.internal.AFa1tSDK.getMonetizationNetwork     // Catch: java.lang.Throwable -> L27
            r8.append(r9)     // Catch: java.lang.Throwable -> L27
            java.lang.String r8 = r8.toString()     // Catch: java.lang.Throwable -> L27
            com.appsflyer.internal.AFc1dSDK r9 = r5.component1     // Catch: java.lang.Throwable -> L27
            com.appsflyer.internal.AFf1gSDK r9 = r9.registerClient()     // Catch: java.lang.Throwable -> L27
            java.lang.String r9 = r9.getMediationNetwork()     // Catch: java.lang.Throwable -> L27
            java.lang.String r3 = "KSAppsFlyerId"
            java.lang.String r3 = r1.getString(r3)     // Catch: java.lang.Throwable -> L27
            com.appsflyer.internal.AFc1dSDK r4 = r5.component1     // Catch: java.lang.Throwable -> L27
            com.appsflyer.internal.AFc1pSDK r4 = r4.getRevenue()     // Catch: java.lang.Throwable -> L27
            com.appsflyer.internal.AFc1qSDK r4 = r4.getMonetizationNetwork     // Catch: java.lang.Throwable -> L27
            java.lang.String r4 = com.appsflyer.internal.AFb1iSDK.getRevenue(r4)     // Catch: java.lang.Throwable -> L27
            r5.getCurrencyIso4217Code(r8, r9, r3, r4)     // Catch: java.lang.Throwable -> L27
            android.content.pm.PackageInfo r7 = r7.getPackageInfo(r6, r2)     // Catch: java.lang.Throwable -> La5
            int r7 = r7.versionCode     // Catch: java.lang.Throwable -> La5
            java.lang.String r8 = "channel"
            java.lang.String r8 = r1.getString(r8)     // Catch: java.lang.Throwable -> La5
            java.lang.String r9 = "preInstallName"
            java.lang.String r9 = r1.getString(r9)     // Catch: java.lang.Throwable -> La5
            java.lang.String r7 = java.lang.String.valueOf(r7)     // Catch: java.lang.Throwable -> La5
            r5.getMonetizationNetwork(r6, r7, r8, r9)     // Catch: java.lang.Throwable -> La5
        La5:
            org.json.JSONObject r6 = new org.json.JSONObject     // Catch: java.lang.Throwable -> L27
            java.util.Map<java.lang.String, java.lang.Object> r7 = r5.AFAdRevenueData     // Catch: java.lang.Throwable -> L27
            r6.<init>(r7)     // Catch: java.lang.Throwable -> L27
            java.lang.String r6 = r6.toString()     // Catch: java.lang.Throwable -> L27
            r1.set(r0, r6)     // Catch: java.lang.Throwable -> L27
            int r6 = com.appsflyer.internal.AFd1kSDK.toString     // Catch: java.lang.Throwable -> L27
            int r6 = r6 + 43
            int r6 = r6 % 128
            com.appsflyer.internal.AFd1kSDK.equals = r6     // Catch: java.lang.Throwable -> L27
        Lbb:
            java.util.Map<java.lang.String, java.lang.Object> r6 = r5.AFAdRevenueData     // Catch: java.lang.Throwable -> L27
            java.lang.String r7 = "launch_counter"
            com.appsflyer.internal.AFc1dSDK r8 = r5.component1     // Catch: java.lang.Throwable -> L27
            com.appsflyer.internal.AFc1pSDK r8 = r8.getRevenue()     // Catch: java.lang.Throwable -> L27
            com.appsflyer.internal.AFc1qSDK r8 = r8.getMonetizationNetwork     // Catch: java.lang.Throwable -> L27
            java.lang.String r9 = "appsFlyerCount"
            int r8 = r8.AFAdRevenueData(r9, r2)     // Catch: java.lang.Throwable -> L27
            java.lang.String r8 = java.lang.String.valueOf(r8)     // Catch: java.lang.Throwable -> L27
            r6.put(r7, r8)     // Catch: java.lang.Throwable -> L27
            monitor-exit(r5)
            return
        Ld6:
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L27
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFd1kSDK.q_(java.lang.String, android.content.pm.PackageManager, com.appsflyer.internal.AFf1gSDK, com.appsflyer.internal.AFc1kSDK):void");
    }

    private boolean registerClient() {
        int i = toString + 9;
        equals = i % 128;
        int i2 = i % 2;
        return this.component1.component2().getMediationNetwork("participantInProxy", false);
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final synchronized void AFAdRevenueData() {
        toString = (equals + 31) % 128;
        this.AFAdRevenueData.clear();
        this.getCurrencyIso4217Code.clear();
        this.getMediationNetwork = 0;
        int i = toString + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED;
        equals = i % 128;
        if (i % 2 == 0) {
            int i2 = 83 / 0;
        }
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final boolean component4() {
        int i = equals;
        int i2 = i + 103;
        toString = i2 % 128;
        if (i2 % 2 != 0) {
            throw null;
        }
        boolean z = this.component4;
        toString = (i + 119) % 128;
        return z;
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final void getCurrencyIso4217Code(String str, String str2) {
        int i = toString + 17;
        equals = i % 128;
        if (i % 2 == 0) {
            String[] strArr = new String[0];
            strArr[0] = str2;
            getCurrencyIso4217Code("server_request", str, strArr);
        } else {
            getCurrencyIso4217Code("server_request", str, str2);
        }
        int i2 = toString + 101;
        equals = i2 % 128;
        if (i2 % 2 == 0) {
            throw null;
        }
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final void getMonetizationNetwork(Throwable th) {
        StackTraceElement[] stackTrace;
        equals = (toString + 45) % 128;
        Throwable cause = th.getCause();
        String simpleName = th.getClass().getSimpleName();
        String message = cause == null ? th.getMessage() : cause.getMessage();
        if (cause == null) {
            int i = equals + 73;
            toString = i % 128;
            if (i % 2 != 0) {
                th.getStackTrace();
                throw null;
            }
            stackTrace = th.getStackTrace();
        } else {
            stackTrace = cause.getStackTrace();
            equals = (toString + 3) % 128;
        }
        getCurrencyIso4217Code("exception", simpleName, getRevenue(message, stackTrace));
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final void getRevenue(String str, int i, String str2) {
        equals = (toString + 29) % 128;
        getCurrencyIso4217Code("server_response", str, String.valueOf(i), str2);
        int i2 = equals + ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND;
        toString = i2 % 128;
        if (i2 % 2 != 0) {
            throw null;
        }
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final void o_(String str, PackageManager packageManager) {
        int i = equals + 117;
        toString = i % 128;
        try {
            if (i % 2 != 0) {
                this.component1.getCurrencyIso4217Code().getRevenue(p_(str, packageManager), this.component1.registerClient().getMediationNetwork());
                throw null;
            }
            AFd1mSDK revenue = this.component1.getCurrencyIso4217Code().getRevenue(p_(str, packageManager), this.component1.registerClient().getMediationNetwork());
            if (revenue == null) {
                AFLogger.afErrorLogForExcManagerOnly("could not send null proxy data", new NullPointerException("request was null"));
                return;
            }
            this.component1.getMonetizationNetwork().execute(new d(revenue, 1));
            int i2 = toString + 19;
            equals = i2 % 128;
            if (i2 % 2 == 0) {
                throw null;
            }
        } catch (Throwable th) {
            AFLogger.afErrorLogForExcManagerOnly("could not send proxy data", th);
        }
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final void getCurrencyIso4217Code() {
        int i = toString + 23;
        int i2 = i % 128;
        equals = i2;
        this.component2 = i % 2 == 0;
        int i3 = i2 + 63;
        toString = i3 % 128;
        if (i3 % 2 != 0) {
            throw null;
        }
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final synchronized void getRevenue() {
        equals = (toString + 125) % 128;
        this.getMonetizationNetwork = false;
        AFAdRevenueData();
        equals();
        toString = (equals + ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND) % 128;
    }

    private synchronized boolean AFAdRevenueData(AFi1xSDK aFi1xSDK, AFi1xSDK aFi1xSDK2) {
        boolean z = false;
        if (aFi1xSDK == null) {
            AFInAppEventParameterName();
            return false;
        }
        if (!aFi1xSDK.getCurrencyIso4217Code()) {
            int i = toString + 77;
            equals = i % 128;
            if (i % 2 != 0) {
                return false;
            }
            throw null;
        }
        if (this.component1.getRevenue().getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0) <= aFi1xSDK.getMonetizationNetwork) {
            if (!getRevenue(aFi1xSDK, aFi1xSDK2)) {
                return false;
            }
            if (!AFAdRevenueData(aFi1xSDK.AFAdRevenueData)) {
                int i2 = equals;
                int i3 = i2 + ContentType.LIVE;
                toString = i3 % 128;
                if (i3 % 2 == 0) {
                    z = true;
                }
                boolean z2 = !z;
                toString = (i2 + 21) % 128;
                return z2;
            }
            if (getCurrencyIso4217Code(aFi1xSDK.component2)) {
                return true;
            }
            int i4 = toString + ContentType.LIVE;
            equals = i4 % 128;
            return i4 % 2 == 0;
        }
        toString = (equals + 3) % 128;
        return false;
    }

    private static /* synthetic */ Object getCurrencyIso4217Code(Object[] objArr) {
        AFd1kSDK aFd1kSDK = (AFd1kSDK) objArr[0];
        if (aFd1kSDK.component2) {
            int i = equals;
            toString = (i + 49) % 128;
            if (aFd1kSDK.getMonetizationNetwork || aFd1kSDK.component4) {
                int i2 = i + 57;
                toString = i2 % 128;
                if (i2 % 2 == 0) {
                    return Boolean.TRUE;
                }
                throw null;
            }
        }
        return Boolean.FALSE;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0033 A[Catch: all -> 0x002f, TRY_ENTER, TRY_LEAVE, TryCatch #1 {, blocks: (B:5:0x000a, B:17:0x0033, B:26:0x0059), top: B:43:0x000a }] */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0059 A[Catch: all -> 0x002f, TRY_ENTER, TRY_LEAVE, TryCatch #1 {, blocks: (B:5:0x000a, B:17:0x0033, B:26:0x0059), top: B:43:0x000a }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private synchronized void getCurrencyIso4217Code(java.lang.String r3, java.lang.String r4, java.lang.String r5, java.lang.String r6) {
        /*
            r2 = this;
            monitor-enter(r2)
            java.util.Map<java.lang.String, java.lang.Object> r0 = r2.AFAdRevenueData     // Catch: java.lang.Throwable -> L82
            java.lang.String r1 = "sdk_version"
            r0.put(r1, r3)     // Catch: java.lang.Throwable -> L82
            if (r4 == 0) goto L31
            int r3 = com.appsflyer.internal.AFd1kSDK.toString     // Catch: java.lang.Throwable -> L2f
            int r3 = r3 + 61
            int r0 = r3 % 128
            com.appsflyer.internal.AFd1kSDK.equals = r0     // Catch: java.lang.Throwable -> L2f
            int r3 = r3 % 2
            if (r3 != 0) goto L21
            int r3 = r4.length()     // Catch: java.lang.Throwable -> L82
            r0 = 47
            int r0 = r0 / 0
            if (r3 <= 0) goto L31
            goto L27
        L21:
            int r3 = r4.length()     // Catch: java.lang.Throwable -> L82
            if (r3 <= 0) goto L31
        L27:
            java.util.Map<java.lang.String, java.lang.Object> r3 = r2.AFAdRevenueData     // Catch: java.lang.Throwable -> L82
            java.lang.String r0 = "devkey"
            r3.put(r0, r4)     // Catch: java.lang.Throwable -> L82
            goto L31
        L2f:
            r3 = move-exception
            goto L7e
        L31:
            if (r5 == 0) goto L57
            int r3 = com.appsflyer.internal.AFd1kSDK.toString     // Catch: java.lang.Throwable -> L2f
            int r3 = r3 + 19
            int r4 = r3 % 128
            com.appsflyer.internal.AFd1kSDK.equals = r4     // Catch: java.lang.Throwable -> L2f
            int r3 = r3 % 2
            if (r3 != 0) goto L4a
            int r3 = r5.length()     // Catch: java.lang.Throwable -> L82
            r4 = 74
            int r4 = r4 / 0
            if (r3 <= 0) goto L57
            goto L50
        L4a:
            int r3 = r5.length()     // Catch: java.lang.Throwable -> L82
            if (r3 <= 0) goto L57
        L50:
            java.util.Map<java.lang.String, java.lang.Object> r3 = r2.AFAdRevenueData     // Catch: java.lang.Throwable -> L82
            java.lang.String r4 = "originalAppsFlyerId"
            r3.put(r4, r5)     // Catch: java.lang.Throwable -> L82
        L57:
            if (r6 == 0) goto L80
            int r3 = com.appsflyer.internal.AFd1kSDK.toString     // Catch: java.lang.Throwable -> L2f
            int r3 = r3 + 61
            int r4 = r3 % 128
            com.appsflyer.internal.AFd1kSDK.equals = r4     // Catch: java.lang.Throwable -> L2f
            int r3 = r3 % 2
            if (r3 != 0) goto L70
            int r3 = r6.length()     // Catch: java.lang.Throwable -> L82
            r4 = 79
            int r4 = r4 / 0
            if (r3 <= 0) goto L80
            goto L76
        L70:
            int r3 = r6.length()     // Catch: java.lang.Throwable -> L82
            if (r3 <= 0) goto L80
        L76:
            java.util.Map<java.lang.String, java.lang.Object> r3 = r2.AFAdRevenueData     // Catch: java.lang.Throwable -> L82
            java.lang.String r4 = "uid"
            r3.put(r4, r6)     // Catch: java.lang.Throwable -> L82
            goto L80
        L7e:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L2f
            throw r3
        L80:
            monitor-exit(r2)
            return
        L82:
            monitor-exit(r2)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFd1kSDK.getCurrencyIso4217Code(java.lang.String, java.lang.String, java.lang.String, java.lang.String):void");
    }

    private static String[] getRevenue(String str, StackTraceElement[] stackTraceElementArr) {
        int i = toString;
        equals = (i + 55) % 128;
        if (stackTraceElementArr != null) {
            String[] strArr = new String[stackTraceElementArr.length + 1];
            strArr[0] = str;
            for (int i2 = 1; i2 < stackTraceElementArr.length; i2++) {
                strArr[i2] = stackTraceElementArr[i2].toString();
            }
            return strArr;
        }
        int i3 = i + 91;
        equals = i3 % 128;
        if (i3 % 2 != 0) {
            return new String[]{str};
        }
        String[] strArr2 = new String[0];
        strArr2[1] = str;
        return strArr2;
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final void getMonetizationNetwork(String str, String str2) {
        int i = toString + 53;
        equals = i % 128;
        if (i % 2 == 0) {
            String[] strArr = new String[1];
            strArr[1] = str2;
            getCurrencyIso4217Code(null, str, strArr);
        } else {
            getCurrencyIso4217Code(null, str, str2);
        }
        int i2 = equals + 45;
        toString = i2 % 128;
        if (i2 % 2 != 0) {
            throw null;
        }
    }

    private synchronized void getMonetizationNetwork(String str, String str2, String str3, String str4) {
        try {
            int i = toString;
            int i2 = i + 71;
            equals = i2 % 128;
            try {
                if (i2 % 2 != 0) {
                    if (str != null) {
                        equals = (i + 35) % 128;
                        if (str.length() > 0) {
                            int i3 = toString + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION;
                            equals = i3 % 128;
                            if (i3 % 2 == 0) {
                                this.AFAdRevenueData.put("app_id", str);
                                int i4 = 52 / 0;
                            } else {
                                this.AFAdRevenueData.put("app_id", str);
                            }
                        }
                    }
                    if (str2 != null && str2.length() > 0) {
                        this.AFAdRevenueData.put("app_version", str2);
                    }
                    if (str3 != null && str3.length() > 0) {
                        this.AFAdRevenueData.put(AppsFlyerProperties.CHANNEL, str3);
                        toString = (equals + 55) % 128;
                    }
                    if (str4 != null && str4.length() > 0) {
                        this.AFAdRevenueData.put("preInstall", str4);
                    }
                } else {
                    throw null;
                }
            } catch (Throwable unused) {
            }
        } finally {
        }
    }

    private boolean getRevenue(@NonNull AFi1xSDK aFi1xSDK, AFi1xSDK aFi1xSDK2) {
        equals = (toString + 87) % 128;
        if (aFi1xSDK.equals(aFi1xSDK2)) {
            equals = (toString + 63) % 128;
            return registerClient();
        }
        boolean monetizationNetwork = getMonetizationNetwork(aFi1xSDK.getRevenue);
        getMediationNetwork(new Object[]{this, Boolean.valueOf(monetizationNetwork)}, 124011145, -124011142, System.identityHashCode(this));
        return monetizationNetwork;
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final synchronized void getMediationNetwork() {
        int i = (toString + 35) % 128;
        equals = i;
        if (!this.component4) {
            int i2 = i + 23;
            toString = i2 % 128;
            if (i2 % 2 == 0) {
                if (!this.getMonetizationNetwork) {
                    return;
                }
                this.component4 = false;
                this.getMonetizationNetwork = false;
                try {
                    getCurrencyIso4217Code("r_debugging_off", new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ", Locale.ENGLISH).format(Long.valueOf(System.currentTimeMillis())), new String[0]);
                    return;
                } catch (Throwable th) {
                    AFLogger.INSTANCE.e(AFg1cSDK.PROXY, "Error while stopping remote debugger", th, true, true, true);
                    return;
                }
            }
            throw null;
        }
        this.component4 = false;
        this.getMonetizationNetwork = false;
        getCurrencyIso4217Code("r_debugging_off", new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ", Locale.ENGLISH).format(Long.valueOf(System.currentTimeMillis())), new String[0]);
        return;
    }

    private synchronized void getCurrencyIso4217Code(String str, String str2, String... strArr) {
        String string;
        if (copydefault()) {
            equals = (toString + 75) % 128;
            if (this.getMediationNetwork < 98304) {
                try {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    String strJoin = TextUtils.join(", ", strArr);
                    if (str != null) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(jCurrentTimeMillis);
                        sb.append(" ");
                        sb.append(Thread.currentThread().getId());
                        sb.append(" _/AppsFlyer_6.17.0 [");
                        sb.append(str);
                        sb.append("] ");
                        sb.append(str2);
                        sb.append(" ");
                        sb.append(strJoin);
                        string = sb.toString();
                    } else {
                        StringBuilder sb2 = new StringBuilder();
                        sb2.append(jCurrentTimeMillis);
                        sb2.append(" ");
                        sb2.append(Thread.currentThread().getId());
                        sb2.append(" ");
                        sb2.append(str2);
                        sb2.append("/AppsFlyer_6.17.0 ");
                        sb2.append(strJoin);
                        string = sb2.toString();
                        toString = (equals + 73) % 128;
                    }
                    int length = this.getMediationNetwork + (string.length() << 1);
                    int i = getRevenue;
                    boolean z = false;
                    if (length > i) {
                        string = string.substring(0, (i - this.getMediationNetwork) / 2);
                        z = true;
                    }
                    this.getCurrencyIso4217Code.add(string);
                    this.getMediationNetwork += string.length() << 1;
                    if (z) {
                        int i2 = toString + 47;
                        equals = i2 % 128;
                        if (i2 % 2 == 0) {
                            this.getCurrencyIso4217Code.add("+~+~ The limit has been exceeded, and no more data is available. +~+~");
                            this.getMediationNetwork += 7164;
                        } else {
                            this.getCurrencyIso4217Code.add("+~+~ The limit has been exceeded, and no more data is available. +~+~");
                            this.getMediationNetwork += 138;
                        }
                    }
                } catch (Throwable unused) {
                }
            }
        }
    }

    private boolean AFAdRevenueData(String str) {
        int i = equals + 125;
        toString = i % 128;
        if (i % 2 != 0) {
            int i2 = 31 / 0;
            if (AFk1ySDK.getCurrencyIso4217Code(str)) {
                return true;
            }
        } else if (AFk1ySDK.getCurrencyIso4217Code(str)) {
            return true;
        }
        Context context = this.component1.getRevenue().getRevenue.getMonetizationNetwork;
        boolean zEquals = str.equals(AFj1iSDK.getMediationNetwork(context, context.getPackageName()));
        int i3 = toString + 93;
        equals = i3 % 128;
        if (i3 % 2 == 0) {
            int i4 = 13 / 0;
        }
        return zEquals;
    }

    private boolean getMonetizationNetwork(float f) {
        double d = f;
        if (d >= 1.0d) {
            return true;
        }
        if (d <= 0.0d) {
            equals = (toString + 39) % 128;
            return false;
        }
        if (component2() > f) {
            return false;
        }
        toString = (equals + 67) % 128;
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x006d A[Catch: all -> 0x0068, TRY_ENTER, TRY_LEAVE, TryCatch #0 {, blocks: (B:5:0x0052, B:13:0x006d), top: B:30:0x0052 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private synchronized void getMediationNetwork(java.lang.String r12, java.lang.String r13, java.lang.String r14) {
        /*
            r11 = this;
            monitor-enter(r11)
            java.util.Map<java.lang.String, java.lang.Object> r0 = r11.AFAdRevenueData     // Catch: java.lang.Throwable -> L9c
            java.lang.String r1 = ""
            r2 = 48
            r3 = 0
            int r1 = android.text.TextUtils.indexOf(r1, r2, r3, r3)     // Catch: java.lang.Throwable -> L9c
            r4 = 428417108(0x19892054, float:1.4178525E-23)
            int r5 = r4 - r1
            java.lang.String r1 = ""
            int r1 = android.text.TextUtils.indexOf(r1, r2, r3)     // Catch: java.lang.Throwable -> L9c
            r2 = 45453(0xb18d, float:6.3693E-41)
            int r2 = r2 - r1
            char r6 = (char) r2     // Catch: java.lang.Throwable -> L9c
            java.lang.String r7 = "嗊褠踙\ue7b1"
            java.lang.String r8 = "ᒸي醼뇗ൎ"
            java.lang.String r9 = "\u0000\u0000\u0000\u0000"
            r1 = 1
            java.lang.Object[] r10 = new java.lang.Object[r1]     // Catch: java.lang.Throwable -> L9c
            a(r5, r6, r7, r8, r9, r10)     // Catch: java.lang.Throwable -> L9c
            r1 = r10[r3]     // Catch: java.lang.Throwable -> L9c
            java.lang.String r1 = (java.lang.String) r1     // Catch: java.lang.Throwable -> L9c
            java.lang.String r1 = r1.intern()     // Catch: java.lang.Throwable -> L9c
            java.lang.String r2 = android.os.Build.BRAND     // Catch: java.lang.Throwable -> L9c
            r0.put(r1, r2)     // Catch: java.lang.Throwable -> L9c
            java.util.Map<java.lang.String, java.lang.Object> r0 = r11.AFAdRevenueData     // Catch: java.lang.Throwable -> L9c
            java.lang.String r1 = "model"
            java.lang.String r2 = android.os.Build.MODEL     // Catch: java.lang.Throwable -> L9c
            r0.put(r1, r2)     // Catch: java.lang.Throwable -> L9c
            java.util.Map<java.lang.String, java.lang.Object> r0 = r11.AFAdRevenueData     // Catch: java.lang.Throwable -> L9c
            java.lang.String r1 = "platform"
            java.lang.String r2 = "Android"
            r0.put(r1, r2)     // Catch: java.lang.Throwable -> L9c
            java.util.Map<java.lang.String, java.lang.Object> r0 = r11.AFAdRevenueData     // Catch: java.lang.Throwable -> L9c
            java.lang.String r1 = "platform_version"
            java.lang.String r2 = android.os.Build.VERSION.RELEASE     // Catch: java.lang.Throwable -> L9c
            r0.put(r1, r2)     // Catch: java.lang.Throwable -> L9c
            if (r12 == 0) goto L6b
            int r0 = com.appsflyer.internal.AFd1kSDK.toString     // Catch: java.lang.Throwable -> L68
            int r0 = r0 + 111
            int r0 = r0 % 128
            com.appsflyer.internal.AFd1kSDK.equals = r0     // Catch: java.lang.Throwable -> L68
            int r0 = r12.length()     // Catch: java.lang.Throwable -> L9c
            if (r0 <= 0) goto L6b
            java.util.Map<java.lang.String, java.lang.Object> r0 = r11.AFAdRevenueData     // Catch: java.lang.Throwable -> L9c
            java.lang.String r1 = "advertiserId"
            r0.put(r1, r12)     // Catch: java.lang.Throwable -> L9c
            goto L6b
        L68:
            r0 = move-exception
            r12 = r0
            goto L89
        L6b:
            if (r13 == 0) goto L8b
            int r12 = com.appsflyer.internal.AFd1kSDK.toString     // Catch: java.lang.Throwable -> L68
            int r12 = r12 + 27
            int r0 = r12 % 128
            com.appsflyer.internal.AFd1kSDK.equals = r0     // Catch: java.lang.Throwable -> L68
            int r12 = r12 % 2
            if (r12 == 0) goto L87
            int r12 = r13.length()     // Catch: java.lang.Throwable -> L9c
            if (r12 <= 0) goto L8b
            java.util.Map<java.lang.String, java.lang.Object> r12 = r11.AFAdRevenueData     // Catch: java.lang.Throwable -> L9c
            java.lang.String r0 = "imei"
            r12.put(r0, r13)     // Catch: java.lang.Throwable -> L9c
            goto L8b
        L87:
            r12 = 0
            throw r12     // Catch: java.lang.Throwable -> L9c
        L89:
            monitor-exit(r11)     // Catch: java.lang.Throwable -> L68
            throw r12
        L8b:
            if (r14 == 0) goto L9a
            int r12 = r14.length()     // Catch: java.lang.Throwable -> L9c
            if (r12 <= 0) goto L9a
            java.util.Map<java.lang.String, java.lang.Object> r12 = r11.AFAdRevenueData     // Catch: java.lang.Throwable -> L9c
            java.lang.String r13 = "android_id"
            r12.put(r13, r14)     // Catch: java.lang.Throwable -> L9c
        L9a:
            monitor-exit(r11)
            return
        L9c:
            monitor-exit(r11)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFd1kSDK.getMediationNetwork(java.lang.String, java.lang.String, java.lang.String):void");
    }

    private static /* synthetic */ Object getMonetizationNetwork(Object[] objArr) {
        AFd1kSDK aFd1kSDK = (AFd1kSDK) objArr[0];
        boolean zBooleanValue = ((Boolean) objArr[1]).booleanValue();
        int i = toString + 41;
        equals = i % 128;
        if (i % 2 == 0) {
            aFd1kSDK.component1.component2().getCurrencyIso4217Code("participantInProxy", zBooleanValue);
            int i2 = 89 / 0;
        } else {
            aFd1kSDK.component1.component2().getCurrencyIso4217Code("participantInProxy", zBooleanValue);
        }
        toString = (equals + 31) % 128;
        return null;
    }

    private static boolean getCurrencyIso4217Code(String str) {
        toString = (equals + 65) % 128;
        if (!AFk1ySDK.getCurrencyIso4217Code(str)) {
            new AFd1sSDK();
            return AFd1sSDK.getMediationNetwork(component1(), str);
        }
        int i = toString + 97;
        equals = i % 128;
        return i % 2 != 0;
    }

    private void getMonetizationNetwork(boolean z) {
        getMediationNetwork(new Object[]{this, Boolean.valueOf(z)}, 124011145, -124011142, System.identityHashCode(this));
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final boolean getMonetizationNetwork() {
        return ((Boolean) getMediationNetwork(new Object[]{this}, -1790300573, 1790300573, System.identityHashCode(this))).booleanValue();
    }

    private static AFi1xSDK getCurrencyIso4217Code(AFi1wSDK aFi1wSDK) {
        if (aFi1wSDK != null) {
            int i = equals + 49;
            int i2 = i % 128;
            toString = i2;
            if (i % 2 == 0) {
                AFh1cSDK aFh1cSDK = aFi1wSDK.getMonetizationNetwork;
                if (aFh1cSDK != null) {
                    AFi1xSDK aFi1xSDK = aFh1cSDK.AFAdRevenueData;
                    equals = (i2 + 51) % 128;
                    return aFi1xSDK;
                }
            } else {
                AFh1cSDK aFh1cSDK2 = aFi1wSDK.getMonetizationNetwork;
                throw null;
            }
        }
        return null;
    }

    @Override // com.appsflyer.internal.AFd1pSDK
    public final void getMediationNetwork(String str, String... strArr) {
        getMediationNetwork(new Object[]{this, str, strArr}, 595413115, -595413114, System.identityHashCode(this));
    }
}
