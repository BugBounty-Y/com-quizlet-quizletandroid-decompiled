package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
final class zzgh implements Runnable, zzpb {
    final /* synthetic */ zzgm zza;

    public /* synthetic */ zzgh(zzgm zzgmVar, zzgl zzglVar) {
        this.zza = zzgmVar;
    }

    @Override // java.lang.Runnable
    public final void run() throws IllegalArgumentException {
        u.k(this.zza.zzm == 1);
        ArrayList arrayList = new ArrayList();
        this.zza.zzp = false;
        if (zzhp.zza().zze(this.zza.zzb)) {
            arrayList.add(0);
        } else {
            zzgm zzgmVar = this.zza;
            zzgmVar.zzp = zzgmVar.zzk.zzf();
            if (this.zza.zzp) {
                arrayList.add(1);
                arrayList.add(0);
            } else {
                arrayList.add(0);
                arrayList.add(1);
            }
            arrayList.add(2);
        }
        zzgm zzgmVar2 = this.zza;
        zzgmVar2.zzf.zzc(zzgmVar2.zzb, zzgmVar2.zzd, zzgmVar2.zzc, arrayList, this, zzgmVar2.zzk);
    }

    @Override // com.google.android.gms.internal.gtm.zzpb
    public final void zza(zzpl zzplVar) {
        if (zzplVar.getStatus() == Status.e) {
            zzgm zzgmVar = this.zza;
            zzgmVar.zzg.execute(new zzgk(zzgmVar, zzplVar));
        } else {
            zzgm zzgmVar2 = this.zza;
            zzgmVar2.zzg.execute(new zzgg(zzgmVar2, null));
        }
    }
}
