package com.google.android.gms.internal.gtm;

import android.net.Uri;

/* loaded from: classes2.dex */
final class zzis implements Runnable {
    final /* synthetic */ Uri zza;
    final /* synthetic */ zzix zzb;

    public zzis(zzix zzixVar, Uri uri) {
        this.zza = uri;
        this.zzb = zzixVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzhi.zzd("Preview requested to uri ".concat(String.valueOf(this.zza)));
        synchronized (this.zzb.zzj) {
            try {
                zzix zzixVar = this.zzb;
                if (zzixVar.zzm == 2) {
                    zzhi.zzd("Still initializing. Defer preview container loading.");
                    this.zzb.zzn.add(this);
                    return;
                }
                String str = (String) zzixVar.zzp(null).first;
                if (str == null) {
                    zzhi.zze("Preview failed (no container found)");
                    return;
                }
                if (!this.zzb.zzh.zzf(str, this.zza)) {
                    zzhi.zze("Cannot preview the app with the uri: " + String.valueOf(this.zza) + ". Launching current version instead.");
                    return;
                }
                if (!this.zzb.zzo) {
                    zzhi.zzd("Deferring container loading for preview uri: " + String.valueOf(this.zza) + "(Tag Manager has not been initialized).");
                    return;
                }
                zzhi.zzc("Starting to load preview container: ".concat(String.valueOf(this.zza)));
                if (!this.zzb.zze.zze()) {
                    zzhi.zze("Failed to reset TagManager service for preview");
                    return;
                }
                this.zzb.zzo = false;
                this.zzb.zzm = 1;
                this.zzb.zzm(null);
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
