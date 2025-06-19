package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.google.android.gms.common.util.a;
import com.google.android.gms.common.util.b;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/* loaded from: classes2.dex */
final class zzii implements zzgs {
    private final String zza;
    private final Context zzb;
    private final zzih zzc;
    private final Map zzd = new HashMap();
    private final Map zze = new HashMap();
    private final a zzf = b.a;

    public zzii(Context context, zzih zzihVar) {
        this.zzb = context.getApplicationContext();
        this.zzc = zzihVar;
        String str = Build.VERSION.RELEASE;
        Locale locale = Locale.getDefault();
        String string = null;
        if (locale != null && locale.getLanguage() != null && locale.getLanguage().length() != 0) {
            StringBuilder sb = new StringBuilder();
            sb.append(locale.getLanguage().toLowerCase());
            if (locale.getCountry() != null && locale.getCountry().length() != 0) {
                sb.append("-");
                sb.append(locale.getCountry().toLowerCase());
            }
            string = sb.toString();
        }
        this.zza = B.j(AbstractC0147y.h("GoogleTagManager/5.06 (Linux; U; Android ", str, "; ", string, "; "), Build.MODEL, " Build/", Build.ID, ")");
    }

    public static final URL zzc(zzgv zzgvVar) {
        try {
            return new URL(zzgvVar.zze());
        } catch (MalformedURLException unused) {
            zzhi.zza("Error trying to parse the GTM url.");
            return null;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x0308  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x0321  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x02ae A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00ac A[Catch: all -> 0x00d0, TryCatch #1 {all -> 0x00d0, blocks: (B:22:0x00a3, B:24:0x00ac, B:25:0x00b4, B:27:0x00ba, B:31:0x00d6, B:37:0x00fb, B:40:0x0107, B:42:0x010d, B:44:0x0113, B:46:0x0119, B:47:0x0138), top: B:136:0x00a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00d6 A[Catch: all -> 0x00d0, TRY_LEAVE, TryCatch #1 {all -> 0x00d0, blocks: (B:22:0x00a3, B:24:0x00ac, B:25:0x00b4, B:27:0x00ba, B:31:0x00d6, B:37:0x00fb, B:40:0x0107, B:42:0x010d, B:44:0x0113, B:46:0x0119, B:47:0x0138), top: B:136:0x00a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00fb A[Catch: all -> 0x00d0, TRY_ENTER, TRY_LEAVE, TryCatch #1 {all -> 0x00d0, blocks: (B:22:0x00a3, B:24:0x00ac, B:25:0x00b4, B:27:0x00ba, B:31:0x00d6, B:37:0x00fb, B:40:0x0107, B:42:0x010d, B:44:0x0113, B:46:0x0119, B:47:0x0138), top: B:136:0x00a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0161  */
    @Override // com.google.android.gms.internal.gtm.zzgs
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zza(java.util.List r17) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 870
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzii.zza(java.util.List):void");
    }

    @Override // com.google.android.gms.internal.gtm.zzgs
    public final boolean zzb() {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) this.zzb.getSystemService("connectivity")).getActiveNetworkInfo();
        if (activeNetworkInfo != null && activeNetworkInfo.isConnected()) {
            return true;
        }
        zzhi.zzd("...no network connectivity");
        return false;
    }
}
