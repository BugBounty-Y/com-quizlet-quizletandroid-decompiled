package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzks extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z = false;
        u.b(zzqoVarArr.length == 2);
        zzqo zzqzVar = zzqoVarArr[0];
        boolean z2 = zzqzVar instanceof zzqw;
        zzqo zzqzVar2 = zzqoVarArr[1];
        if (z2 || (zzqzVar instanceof zzqv) || (zzqzVar instanceof zzqr)) {
            zzqzVar = new zzqz(zzjn.zzd(zzqzVar));
        }
        if ((zzqzVar2 instanceof zzqw) || (zzqzVar2 instanceof zzqv) || (zzqzVar2 instanceof zzqr)) {
            zzqzVar2 = new zzqz(zzjn.zzd(zzqzVar2));
        }
        if (((zzqzVar instanceof zzqz) && (zzqzVar2 instanceof zzqz)) || (!Double.isNaN(zzjn.zzb(zzqzVar)) && !Double.isNaN(zzjn.zzb(zzqzVar2)))) {
            z = !zzjn.zzf(zzqzVar2, zzqzVar);
        }
        return new zzqp(Boolean.valueOf(z));
    }
}
