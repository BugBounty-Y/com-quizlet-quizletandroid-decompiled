package com.google.android.gms.internal.gtm;

import java.util.Iterator;

/* loaded from: classes2.dex */
final class zzja implements Runnable {
    final /* synthetic */ zzjb zza;

    public zzja(zzjb zzjbVar) {
        this.zza = zzjbVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.zza.zza.isEmpty()) {
            zzhi.zze("TagManagerBackend dispatch called without loaded container.");
            return;
        }
        Iterator it2 = this.zza.zza.values().iterator();
        while (it2.hasNext()) {
            ((zzgm) it2.next()).zzs();
        }
    }
}
