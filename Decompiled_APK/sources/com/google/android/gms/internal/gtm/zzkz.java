package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzkz implements zzjm {
    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 3);
        zzqo zzqoVarZzc = zzjn.zzg(zzra.zzc(zzhxVar, zzqoVarArr[0])) ? zzra.zzc(zzhxVar, zzqoVarArr[1]) : zzra.zzc(zzhxVar, zzqoVarArr[2]);
        if (!(zzqoVarZzc instanceof zzqs) || zzqoVarZzc == zzqs.zze || zzqoVarZzc == zzqs.zzd) {
            return zzqoVarZzc;
        }
        throw new IllegalArgumentException("Illegal InternalType passed to Ternary.");
    }
}
