package com.google.android.gms.internal.gtm;

import android.net.Uri;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

/* loaded from: classes2.dex */
public final class zzhp {
    private static zzhp zza;
    private volatile int zzd = 1;
    private volatile String zzc = null;
    private volatile String zzb = null;

    public static zzhp zza() {
        zzhp zzhpVar;
        synchronized (zzhp.class) {
            try {
                if (zza == null) {
                    zza = new zzhp();
                }
                zzhpVar = zza;
            } catch (Throwable th) {
                throw th;
            }
        }
        return zzhpVar;
    }

    public final String zzb() {
        return this.zzc;
    }

    public final String zzc() {
        return this.zzb;
    }

    public final boolean zzd() {
        return this.zzd == 2;
    }

    public final boolean zze(String str) {
        return zzd() && this.zzb.equals(str);
    }

    public final synchronized boolean zzf(String str, Uri uri) {
        try {
            String strDecode = URLDecoder.decode(uri.toString(), "UTF-8");
            if (!strDecode.matches("^tagmanager.c.\\S+:\\/\\/preview\\/p\\S+")) {
                zzhi.zze("Bad preview url: ".concat(strDecode));
                return false;
            }
            String queryParameter = uri.getQueryParameter("id");
            String queryParameter2 = uri.getQueryParameter("gtm_auth");
            String queryParameter3 = uri.getQueryParameter("gtm_preview");
            if (!str.equals(queryParameter)) {
                zzhi.zze("Preview fails (container doesn't match the container specified by the asset)");
                return false;
            }
            if (queryParameter == null || queryParameter.length() <= 0) {
                zzhi.zze("Bad preview url: ".concat(strDecode));
                return false;
            }
            if (queryParameter3 != null && queryParameter3.length() == 0) {
                if (queryParameter.equals(this.zzb) && this.zzd != 1) {
                    zzhi.zzd("Exit preview mode for container: ".concat(String.valueOf(this.zzb)));
                    this.zzd = 1;
                    this.zzb = null;
                    this.zzc = null;
                }
                zzhi.zze("Error in exiting preview mode. The container is not in preview.");
                return false;
            }
            if (queryParameter3 == null || queryParameter3.length() <= 0 || queryParameter2 == null || queryParameter2.length() <= 0) {
                zzhi.zze("Bad preview url: ".concat(strDecode));
                return false;
            }
            this.zzd = 2;
            this.zzc = uri.getQuery();
            this.zzb = queryParameter;
            return true;
        } catch (UnsupportedEncodingException e) {
            zzhi.zze("Error decoding the preview url: ".concat(e.toString()));
            return false;
        }
    }
}
