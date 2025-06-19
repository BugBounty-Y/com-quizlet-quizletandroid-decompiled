package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
final class zzgj implements Runnable, zzpb {
    final /* synthetic */ zzgm zza;

    @Override // java.lang.Runnable
    public final void run() throws IllegalArgumentException {
        u.k(this.zza.zzm == 2);
        if (zzhp.zza().zze(this.zza.zzb)) {
            return;
        }
        zzhi.zzd("Refreshing container " + this.zza.zzb + "...");
        ArrayList arrayList = new ArrayList();
        arrayList.add(0);
        zzgm zzgmVar = this.zza;
        zzgmVar.zzf.zzc(zzgmVar.zzb, zzgmVar.zzd, zzgmVar.zzc, arrayList, this, zzgmVar.zzk);
    }

    @Override // com.google.android.gms.internal.gtm.zzpb
    public final void zza(zzpl zzplVar) {
        if (zzplVar.getStatus() != Status.e) {
            zzgm zzgmVar = this.zza;
            zzgm.zzr(zzgmVar, zzgmVar.zzk.zzc());
            return;
        }
        zzhi.zzd("Refreshed container " + this.zza.zzb + ". Reinitializing runtime...");
        zzgm zzgmVar2 = this.zza;
        zzgmVar2.zzg.execute(new zzgk(zzgmVar2, zzplVar));
    }
}
