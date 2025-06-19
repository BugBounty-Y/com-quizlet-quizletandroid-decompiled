package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/* loaded from: classes2.dex */
public final class zzpr {
    private final String zza = "https://www.google-analytics.com";

    private static final String zzb(String str) {
        try {
            return URLEncoder.encode(str, "UTF-8").replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException unused) {
            zzhi.zza("Cannot encode the string: ".concat(String.valueOf(str)));
            return "";
        }
    }

    public final String zza(zzox zzoxVar) {
        String string;
        if (zzoxVar.zzg()) {
            string = zzoxVar.zza();
        } else {
            String strTrim = !zzoxVar.zze().trim().isEmpty() ? zzoxVar.zze().trim() : "-1";
            StringBuilder sb = new StringBuilder();
            if (zzoxVar.zzf() != null) {
                sb.append(zzoxVar.zzf());
            } else {
                sb.append("id");
            }
            sb.append(SimpleComparison.EQUAL_TO_OPERATION);
            sb.append(zzb(zzoxVar.zzb()));
            sb.append("&pv=");
            sb.append(zzb(strTrim));
            sb.append("&rv=5.0");
            if (zzoxVar.zzg()) {
                sb.append("&gtm_debug=x");
            }
            string = sb.toString();
        }
        return a.l(this.zza, "/gtm/android?", string);
    }
}
