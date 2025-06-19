package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class zzhh {
    private static String zza;

    static {
        new HashMap();
    }

    public static String zza(String str, String str2) {
        if (str2 != null) {
            return Uri.parse("http://hostname/?".concat(String.valueOf(str))).getQueryParameter(str2);
        }
        if (str.length() > 0) {
            return str;
        }
        return null;
    }

    public static String zzb(Context context, String str) {
        if (zza == null) {
            synchronized (zzhh.class) {
                try {
                    if (zza == null) {
                        SharedPreferences sharedPreferences = context.getSharedPreferences("gtm_install_referrer", 0);
                        if (sharedPreferences != null) {
                            zza = sharedPreferences.getString("referrer", "");
                        } else {
                            zza = "";
                        }
                    }
                } finally {
                }
            }
        }
        return zza(zza, str);
    }
}
