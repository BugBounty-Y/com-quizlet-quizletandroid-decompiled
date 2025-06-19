package com.appsflyer.internal;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Process;
import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/* loaded from: classes.dex */
public final class AFj1iSDK {
    public static boolean AFAdRevenueData(Context context) {
        if (context != null) {
            try {
                if (GoogleApiAvailability.d.c(context, com.google.android.gms.common.c.a) == 0) {
                    return true;
                }
            } catch (Throwable unused) {
            }
        }
        return false;
    }

    public static boolean L_(Context context, Intent intent) {
        return context.getPackageManager().queryIntentServices(intent, 0).size() > 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x005a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.Map<java.lang.String, java.lang.String> M_(android.content.Context r9, java.util.Map<java.lang.String, java.lang.String> r10, android.net.Uri r11) {
        /*
            r0 = 0
            java.lang.String r1 = "install_time"
            java.util.Set r2 = r11.getQueryParameterNames()
            java.util.Iterator r2 = r2.iterator()
        Lb:
            boolean r3 = r2.hasNext()
            java.lang.String r4 = "media_source"
            java.lang.String r5 = "agency"
            if (r3 == 0) goto L5f
            java.lang.Object r3 = r2.next()
            java.lang.String r3 = (java.lang.String) r3
            java.lang.String r6 = r11.getQueryParameter(r3)
            boolean r7 = r10.containsKey(r3)
            if (r7 != 0) goto L5a
            r3.getClass()
            r7 = -1
            int r8 = r3.hashCode()
            switch(r8) {
                case -1420799080: goto L47;
                case 99: goto L3c;
                case 110987: goto L31;
                default: goto L30;
            }
        L30:
            goto L51
        L31:
            java.lang.String r8 = "pid"
            boolean r8 = r3.equals(r8)
            if (r8 != 0) goto L3a
            goto L51
        L3a:
            r7 = 2
            goto L51
        L3c:
            java.lang.String r8 = "c"
            boolean r8 = r3.equals(r8)
            if (r8 != 0) goto L45
            goto L51
        L45:
            r7 = 1
            goto L51
        L47:
            java.lang.String r8 = "af_prt"
            boolean r8 = r3.equals(r8)
            if (r8 != 0) goto L50
            goto L51
        L50:
            r7 = r0
        L51:
            switch(r7) {
                case 0: goto L58;
                case 1: goto L55;
                case 2: goto L5b;
                default: goto L54;
            }
        L54:
            goto L5a
        L55:
            java.lang.String r4 = "campaign"
            goto L5b
        L58:
            r4 = r5
            goto L5b
        L5a:
            r4 = r3
        L5b:
            r10.put(r4, r6)
            goto Lb
        L5f:
            boolean r2 = r10.containsKey(r1)     // Catch: java.lang.Exception -> L92
            if (r2 != 0) goto L98
            java.lang.String r2 = "yyyy-MM-dd HH:mm:ss"
            java.text.SimpleDateFormat r3 = new java.text.SimpleDateFormat     // Catch: java.lang.Exception -> L92
            java.util.Locale r6 = java.util.Locale.US     // Catch: java.lang.Exception -> L92
            r3.<init>(r2, r6)     // Catch: java.lang.Exception -> L92
            android.content.pm.PackageManager r2 = r9.getPackageManager()     // Catch: java.lang.Exception -> L92
            java.lang.String r9 = r9.getPackageName()     // Catch: java.lang.Exception -> L92
            android.content.pm.PackageInfo r9 = r2.getPackageInfo(r9, r0)     // Catch: java.lang.Exception -> L92
            long r6 = r9.firstInstallTime     // Catch: java.lang.Exception -> L92
            java.lang.String r9 = "UTC"
            java.util.TimeZone r9 = java.util.TimeZone.getTimeZone(r9)     // Catch: java.lang.Exception -> L92
            r3.setTimeZone(r9)     // Catch: java.lang.Exception -> L92
            java.util.Date r9 = new java.util.Date     // Catch: java.lang.Exception -> L92
            r9.<init>(r6)     // Catch: java.lang.Exception -> L92
            java.lang.String r9 = r3.format(r9)     // Catch: java.lang.Exception -> L92
            r10.put(r1, r9)     // Catch: java.lang.Exception -> L92
            goto L98
        L92:
            r9 = move-exception
            java.lang.String r0 = "Could not fetch install time. "
            com.appsflyer.AFLogger.afErrorLog(r0, r9)
        L98:
            java.lang.String r9 = "af_deeplink"
            boolean r9 = r10.containsKey(r9)
            if (r9 == 0) goto Lad
            java.lang.String r9 = "af_status"
            boolean r0 = r10.containsKey(r9)
            if (r0 != 0) goto Lad
            java.lang.String r0 = "Non-organic"
            r10.put(r9, r0)
        Lad:
            boolean r9 = r10.containsKey(r5)
            if (r9 == 0) goto Lb6
            r10.remove(r4)
        Lb6:
            java.lang.String r9 = r11.getPath()
            if (r9 == 0) goto Lc1
            java.lang.String r0 = "path"
            r10.put(r0, r9)
        Lc1:
            java.lang.String r9 = r11.getScheme()
            if (r9 == 0) goto Lcc
            java.lang.String r0 = "scheme"
            r10.put(r0, r9)
        Lcc:
            java.lang.String r9 = r11.getHost()
            if (r9 == 0) goto Ld7
            java.lang.String r11 = "host"
            r10.put(r11, r9)
        Ld7:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFj1iSDK.M_(android.content.Context, java.util.Map, android.net.Uri):java.util.Map");
    }

    @SuppressLint({"PackageManagerGetSignatures"})
    public static String N_(PackageManager packageManager, String str) throws NoSuchAlgorithmException, PackageManager.NameNotFoundException, CertificateException {
        Signature[] signatureArr = packageManager.getPackageInfo(str, 64).signatures;
        if (signatureArr == null) {
            return null;
        }
        X509Certificate x509Certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(signatureArr[0].toByteArray()));
        MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
        messageDigest.update(x509Certificate.getEncoded());
        return String.format("%032X", new BigInteger(1, messageDigest.digest()));
    }

    public static Application O_(@NonNull Context context) {
        if (context instanceof Application) {
            return (Application) context;
        }
        if (context instanceof Activity) {
            return ((Activity) context).getApplication();
        }
        try {
            return (Application) context.getApplicationContext();
        } catch (ClassCastException unused) {
            AFLogger.afErrorLog("Application or Activity Context should be used", new IllegalStateException(), true, true);
            return null;
        }
    }

    public static boolean getCurrencyIso4217Code(Context context) {
        if (context == null) {
            return false;
        }
        try {
            new com.google.android.gms.internal.appset.g(context);
            return true;
        } catch (Throwable unused) {
            return false;
        }
    }

    public static boolean getMediationNetwork() {
        return Build.BRAND.equals("OPPO");
    }

    public static boolean getMonetizationNetwork(Context context) {
        if (context == null) {
            return false;
        }
        try {
            IntegrityManagerFactory.create(context);
            return true;
        } catch (Throwable unused) {
            return false;
        }
    }

    @SuppressLint({"NewApi"})
    public static boolean getRevenue(Context context) {
        if (context == null || Build.VERSION.SDK_INT < 33) {
            return false;
        }
        try {
            return androidx.credentials.i.k(context.getApplicationContext().getSystemService(androidx.credentials.i.t())) != null;
        } catch (Throwable th) {
            AFLogger.INSTANCE.e(AFg1cSDK.PRIVACY_SANDBOX, th.getMessage() != null ? th.getMessage() : "", th, false, false);
            return false;
        }
    }

    public static String getMediationNetwork(Context context, String str) {
        try {
            return context.getPackageManager().getPackageInfo(str, 0).versionName;
        } catch (PackageManager.NameNotFoundException e) {
            AFLogger.afErrorLog(e.getMessage(), e);
            return "";
        }
    }

    public static boolean getMonetizationNetwork(Context context, String str) {
        int iCheckPermission = context.checkPermission(str, Process.myPid(), Process.myUid());
        StringBuilder sb = new StringBuilder("is Permission Available: ");
        sb.append(str);
        sb.append("; res: ");
        sb.append(iCheckPermission);
        AFLogger.afRDLog(sb.toString());
        return iCheckPermission == 0;
    }

    public static long AFAdRevenueData(Context context, String str) throws PackageManager.NameNotFoundException {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(str, 0);
            if (Build.VERSION.SDK_INT >= 28) {
                return packageInfo.getLongVersionCode();
            }
            return packageInfo.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            AFLogger.afErrorLog(e.getMessage(), e);
            return 0L;
        }
    }
}
