package com.google.android.gms.internal.gtm;

/* loaded from: classes2.dex */
final class zzip implements Runnable {
    final /* synthetic */ zzix zza;

    public zzip(zzix zzixVar) {
        this.zza = zzixVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.zza.zzf.execute(new zzio(this));
    }
}
