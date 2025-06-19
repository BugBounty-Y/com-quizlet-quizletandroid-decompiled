package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzlx extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 2);
        zzqo zzqzVar = zzqoVarArr[0];
        boolean z = zzqzVar instanceof zzqs;
        zzqo zzqzVar2 = zzqoVarArr[1];
        if ((z && zzqzVar != zzqs.zze && zzqzVar != zzqs.zzd) || ((zzqzVar2 instanceof zzqs) && zzqzVar2 != zzqs.zze && zzqzVar2 != zzqs.zzd)) {
            throw new IllegalArgumentException("Illegal InternalType passed to Add.");
        }
        if ((zzqzVar instanceof zzqw) || (zzqzVar instanceof zzqv) || (zzqzVar instanceof zzqr)) {
            zzqzVar = new zzqz(zzjn.zzd(zzqzVar));
        }
        if ((zzqzVar2 instanceof zzqw) || (zzqzVar2 instanceof zzqv) || (zzqzVar2 instanceof zzqr)) {
            zzqzVar2 = new zzqz(zzjn.zzd(zzqzVar2));
        }
        if ((zzqzVar instanceof zzqz) || (zzqzVar2 instanceof zzqz)) {
            return new zzqz(String.valueOf(zzjn.zzd(zzqzVar)).concat(String.valueOf(zzjn.zzd(zzqzVar2))));
        }
        return new zzqq(Double.valueOf(zzjn.zzc(zzqzVar, zzqzVar2)));
    }
}
