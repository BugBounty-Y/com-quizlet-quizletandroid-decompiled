package com.google.ads.conversiontracking;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;
import androidx.compose.ui.node.B;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_common.P2;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;

/* loaded from: classes2.dex */
public abstract class r {
    public static final HashMap a = new HashMap();
    public static final Object b = new Object();
    public static l c = null;

    public static String a(long j) {
        return String.format(Locale.US, "%d.%03d", Long.valueOf(j / 1000), Long.valueOf(j % 1000));
    }

    public static String b(Context context, q qVar) throws NoSuchAlgorithmException {
        androidx.room.s sVarD;
        String str;
        int i;
        String str2;
        String str3;
        String str4;
        String str5;
        String str6;
        String strJ;
        String str7;
        String string;
        char[] cArr;
        try {
            sVarD = P2.d(new d(context).a);
        } catch (j | k | IOException | IllegalStateException unused) {
            sVarD = null;
        }
        String packageName = context.getPackageName();
        try {
            str = context.getPackageManager().getPackageInfo(packageName, 0).versionName;
        } catch (PackageManager.NameNotFoundException e) {
            Log.w("GoogleConversionReporter", "Error to retrieve app version", e);
            str = "";
        }
        if (sVarD == null) {
            String string2 = Settings.Secure.getString(context.getContentResolver(), "android_id");
            if (string2 == null) {
                string2 = "null";
            }
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(string2.getBytes());
            byte[] bArrDigest = messageDigest.digest();
            char[] cArr2 = y.a;
            int length = bArrDigest.length;
            int i2 = ((length + 2) / 3) * 4;
            int i3 = (i2 / SubsamplingScaleImageView.TILE_SIZE_AUTO) + i2;
            char[] cArr3 = new char[i3];
            i = 4;
            int i4 = length - 2;
            int i5 = 0;
            int i6 = 0;
            int i7 = 0;
            while (true) {
                cArr = y.a;
                if (i5 >= i4) {
                    break;
                }
                int i8 = ((bArrDigest[i5] << 24) >>> 8) | ((bArrDigest[i5 + 1] << 24) >>> 16) | ((bArrDigest[i5 + 2] << 24) >>> 24);
                cArr3[i6] = cArr[i8 >>> 18];
                int i9 = i6 + 1;
                cArr3[i9] = cArr[(i8 >>> 12) & 63];
                cArr3[i6 + 2] = cArr[(i8 >>> 6) & 63];
                cArr3[i6 + 3] = cArr[i8 & 63];
                int i10 = i7 + 4;
                if (i10 == Integer.MAX_VALUE) {
                    cArr3[i6 + 4] = '\n';
                    i6 = i9;
                    i7 = 0;
                } else {
                    i7 = i10;
                }
                i5 += 3;
                i6 += 4;
            }
            if (i5 < length) {
                int i11 = length - i5;
                int i12 = (i11 > 2 ? (bArrDigest[i5 + 2] << 24) >>> 24 : 0) | (i11 > 0 ? (bArrDigest[i5] << 24) >>> 8 : 0) | (i11 > 1 ? (bArrDigest[i5 + 1] << 24) >>> 16 : 0);
                if (i11 == 1) {
                    cArr3[i6] = cArr[i12 >>> 18];
                    cArr3[i6 + 1] = cArr[(i12 >>> 12) & 63];
                    cArr3[i6 + 2] = '=';
                    cArr3[i6 + 3] = '=';
                } else if (i11 == 2) {
                    cArr3[i6] = cArr[i12 >>> 18];
                    cArr3[i6 + 1] = cArr[(i12 >>> 12) & 63];
                    cArr3[i6 + 2] = cArr[(i12 >>> 6) & 63];
                    cArr3[i6 + 3] = '=';
                } else if (i11 == 3) {
                    cArr3[i6] = cArr[i12 >>> 18];
                    cArr3[i6 + 1] = cArr[(i12 >>> 12) & 63];
                    cArr3[i6 + 2] = cArr[(i12 >>> 6) & 63];
                    cArr3[i6 + 3] = cArr[i12 & 63];
                }
                if (i7 + 4 == Integer.MAX_VALUE) {
                    cArr3[i6 + 4] = '\n';
                }
            }
            while (i3 > 0 && cArr3[i3 - 1] == '=') {
                i3--;
            }
            str2 = new String(cArr3, 0, i3);
        } else {
            i = 4;
            str2 = null;
        }
        int i13 = qVar.c;
        if (i13 == 2) {
            String str8 = qVar.a;
            String strValueOf = String.valueOf(Build.VERSION.RELEASE);
            String strA = a(System.currentTimeMillis());
            StringBuilder sb = new StringBuilder(strA.length() + strValueOf.length() + String.valueOf(str).length() + String.valueOf(packageName).length() + String.valueOf(str8).length() + 70 + 10 + 9 + 34);
            B.u(sb, "https://pubads.g.doubleclick.net/activity;xsp=", str8, ";ait=1;bundleid=", packageName);
            B.u(sb, ";appversion=", str, ";osversion=", strValueOf);
            StringBuilder sb2 = new StringBuilder(android.support.v4.media.session.a.t(sb, ";sdkversion=ct-sdk-a-v2.2.4;timestamp=", strA));
            c(sb2, sVarD, str2);
            return sb2.toString();
        }
        if (i13 == 1) {
            if (sVarD == null) {
                string = null;
            } else {
                String strValueOf2 = String.valueOf(qVar.e);
                StringBuilder sb3 = new StringBuilder(strValueOf2.length() != 0 ? "https://pubads.g.doubleclick.net/activity;dc_iu=".concat(strValueOf2) : new String("https://pubads.g.doubleclick.net/activity;dc_iu="));
                c(sb3, sVarD, null);
                string = sb3.toString();
            }
            return string;
        }
        String str9 = str2;
        if (i13 == i) {
            Uri.Builder builderAppendQueryParameter = Uri.parse("https://www.googleadservices.com/pagead/conversion/").buildUpon().appendQueryParameter("sku", null).appendQueryParameter("value", qVar.e).appendQueryParameter("bundleid", packageName).appendQueryParameter("appversion", str).appendQueryParameter("osversion", Build.VERSION.RELEASE).appendQueryParameter("sdkversion", "ct-sdk-a-v2.2.4").appendQueryParameter("timestamp", a(System.currentTimeMillis()));
            if ((sVarD == null ? null : sVarD.c ? "1" : "0") != null) {
                builderAppendQueryParameter.appendQueryParameter("lat", sVarD == null ? null : sVarD.c ? "1" : "0");
            }
            if (sVarD != null) {
                builderAppendQueryParameter.appendQueryParameter("rdid", sVarD.b);
            } else {
                builderAppendQueryParameter.appendQueryParameter("muid", str9);
            }
            return builderAppendQueryParameter.build().toString();
        }
        com.quizlet.data.interactor.school.e eVar = qVar.f;
        if (eVar == null) {
            str5 = str9;
            str6 = "muid";
            str4 = "value";
            strJ = "";
            str3 = "timestamp";
        } else {
            str3 = "timestamp";
            String str10 = (String) eVar.c;
            boolean zIsEmpty = TextUtils.isEmpty(str10);
            str4 = "value";
            String str11 = (String) eVar.b;
            if (zIsEmpty) {
                String strValueOf3 = String.valueOf(str11);
                strJ = strValueOf3.length() != 0 ? "&gclid=".concat(strValueOf3) : new String("&gclid=");
                str5 = str9;
                str6 = "muid";
            } else {
                str5 = str9;
                str6 = "muid";
                strJ = B.j(new StringBuilder(String.valueOf(str10).length() + String.valueOf(str11).length() + 11), "&gclid=", str11, "&ai=", str10);
            }
        }
        Uri.Builder builderAppendQueryParameter2 = Uri.parse("https://www.googleadservices.com/pagead/conversion/").buildUpon().appendEncodedPath(String.valueOf(qVar.a).concat("/")).appendQueryParameter("bundleid", packageName).appendQueryParameter("appversion", str).appendQueryParameter("osversion", Build.VERSION.RELEASE).appendQueryParameter("sdkversion", "ct-sdk-a-v2.2.4").appendQueryParameter("gms", sVarD != null ? "1" : "0");
        if ((sVarD == null ? null : sVarD.c ? "1" : "0") != null) {
            builderAppendQueryParameter2.appendQueryParameter("lat", sVarD == null ? null : sVarD.c ? "1" : "0");
        }
        if (sVarD != null) {
            builderAppendQueryParameter2.appendQueryParameter("rdid", sVarD.b);
        } else {
            builderAppendQueryParameter2.appendQueryParameter(str6, str5);
        }
        String str12 = qVar.d;
        if (str12 != null && qVar.e != null) {
            builderAppendQueryParameter2.appendQueryParameter("label", str12).appendQueryParameter(str4, qVar.e);
        }
        long j = qVar.g;
        if (j != 0) {
            builderAppendQueryParameter2.appendQueryParameter(str3, a(j));
        } else {
            builderAppendQueryParameter2.appendQueryParameter(str3, a(System.currentTimeMillis()));
        }
        if (qVar.h) {
            str7 = "1";
            builderAppendQueryParameter2.appendQueryParameter("auto", str7);
        } else {
            str7 = "1";
        }
        if (qVar.b) {
            builderAppendQueryParameter2.appendQueryParameter("usage_tracking_enabled", str7);
        } else {
            builderAppendQueryParameter2.appendQueryParameter("usage_tracking_enabled", "0");
        }
        String strValueOf4 = String.valueOf(builderAppendQueryParameter2.build());
        return android.support.v4.media.session.a.t(new StringBuilder(String.valueOf(strJ).length() + strValueOf4.length()), strValueOf4, strJ);
    }

    public static void c(StringBuilder sb, androidx.room.s sVar, String str) {
        String str2 = sVar == null ? null : sVar.c ? "1" : "0";
        if (str2 != null) {
            sb.append(str2.length() != 0 ? ";dc_lat=".concat(str2) : new String(";dc_lat="));
        }
        if (sVar == null) {
            String strValueOf = String.valueOf(str);
            sb.append(strValueOf.length() != 0 ? ";isu=".concat(strValueOf) : new String(";isu="));
        } else {
            String strValueOf2 = String.valueOf(sVar.b);
            sb.append(strValueOf2.length() != 0 ? ";dc_rdid=".concat(strValueOf2) : new String(";dc_rdid="));
        }
    }

    public static boolean d(Context context, String str, String str2, boolean z) {
        if (z) {
            return true;
        }
        boolean z2 = context.getSharedPreferences(str, 0).getBoolean(str2, false);
        if (z2) {
            String strValueOf = String.valueOf(str2);
            Log.i("GoogleConversionReporter", strValueOf.length() != 0 ? "Already sent ping for conversion ".concat(strValueOf) : new String("Already sent ping for conversion "));
        }
        return !z2;
    }
}
