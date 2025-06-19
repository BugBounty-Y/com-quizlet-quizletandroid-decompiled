package com.google.android.gms.internal.gtm;

import java.util.Iterator;

/* loaded from: classes2.dex */
final class zziz implements Runnable {
    final /* synthetic */ zzgt zza;
    final /* synthetic */ zzjb zzb;

    public zziz(zzjb zzjbVar, zzgt zzgtVar) {
        this.zza = zzgtVar;
        this.zzb = zzjbVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (this.zzb.zza.isEmpty()) {
            zzhi.zza("TagManagerBackend emit called without loaded container.");
            return;
        }
        Iterator it2 = this.zzb.zza.values().iterator();
        while (it2.hasNext()) {
            ((zzgm) it2.next()).zzt(this.zza);
        }
    }
}
