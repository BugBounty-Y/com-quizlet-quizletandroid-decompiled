package com.google.android.gms.internal.gtm;

import android.os.Bundle;
import android.os.RemoteException;
import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
final class zzij implements Runnable {
    final /* synthetic */ String zza;
    final /* synthetic */ Bundle zzb;
    final /* synthetic */ String zzc;
    final /* synthetic */ long zzd;
    final /* synthetic */ String zze;
    final /* synthetic */ zzik zzf;
    private boolean zzg = false;

    public zzij(zzik zzikVar, String str, Bundle bundle, String str2, long j, String str3) {
        this.zza = str;
        this.zzb = bundle;
        this.zzc = str2;
        this.zzd = j;
        this.zze = str3;
        this.zzf = zzikVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzix zzixVar = this.zzf.zza;
        if (zzixVar.zzm == 3) {
            zzixVar.zze.zzb(this.zza, this.zzb, this.zzc, this.zzd, true);
            return;
        }
        if (zzixVar.zzm == 4) {
            String str = this.zza;
            String str2 = this.zzc;
            Bundle bundle = this.zzb;
            StringBuilder sbH = AbstractC0147y.h("Container failed to load: skipping  event interceptor by logging event back to Firebase directly: name = ", str, ", origin = ", str2, ", params = ");
            sbH.append(bundle);
            sbH.append(".");
            zzhi.zzd(sbH.toString());
            try {
                this.zzf.zza.zzd.zzc(this.zzc, this.zza, this.zzb, this.zzd);
                return;
            } catch (RemoteException e) {
                zzgp.zzb("Error logging event on measurement proxy: ", e, this.zzf.zza.zzc);
                return;
            }
        }
        if (zzixVar.zzm != 1 && zzixVar.zzm != 2) {
            zzgp.zzc(a.f(zzixVar.zzm, "Unexpected state:"), this.zzf.zza.zzc);
            return;
        }
        if (this.zzg) {
            zzgp.zzc("Invalid state - not expecting to see a deferredevent during container loading.", zzixVar.zzc);
            return;
        }
        String str3 = this.zza;
        String str4 = this.zze;
        Bundle bundle2 = this.zzb;
        StringBuilder sbH2 = AbstractC0147y.h("Container not loaded yet: deferring event interceptor by enqueuing the event: name = ", str3, ", origin = ", str4, ", params = ");
        sbH2.append(bundle2);
        sbH2.append(".");
        zzhi.zzd(sbH2.toString());
        this.zzg = true;
        this.zzf.zza.zzn.add(this);
    }
}
