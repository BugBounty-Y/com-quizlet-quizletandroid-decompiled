package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzio implements Runnable {
    final /* synthetic */ zzip zza;

    public zzio(zzip zzipVar) {
        this.zza = zzipVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        zzix zzixVar = this.zza.zza;
        if (zzixVar.zzm == 1 || zzixVar.zzm == 2) {
            zzixVar.zzm = 4;
            zzhi.zza("Container load timed out after 5000ms.");
            while (!this.zza.zza.zzn.isEmpty()) {
                zzix zzixVar2 = this.zza.zza;
                zzixVar2.zzf.execute((Runnable) zzixVar2.zzn.remove());
            }
        }
    }
}
