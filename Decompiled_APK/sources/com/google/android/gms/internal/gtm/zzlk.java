package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzlk implements zzjm {
    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 1);
        u.b(zzqoVarArr[0] instanceof zzqz);
        zzqo zzqoVarZzb = zzhxVar.zzb(((zzqz) zzqoVarArr[0]).zzk());
        if (zzqoVarZzb instanceof zzqx) {
            throw new IllegalStateException("Illegal Statement type encountered in Get.");
        }
        if (!(zzqoVarZzb instanceof zzqs) || zzqoVarZzb == zzqs.zze || zzqoVarZzb == zzqs.zzd) {
            return zzqoVarZzb;
        }
        throw new IllegalStateException("Illegal InternalType encountered in Get.");
    }
}
