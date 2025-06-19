package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public abstract class zzjo implements zzjm {
    public abstract zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr);

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        zzqo[] zzqoVarArr2 = new zzqo[zzqoVarArr.length];
        for (int i = 0; i < zzqoVarArr.length; i++) {
            u.b(zzqoVarArr[i] != null);
            zzqo zzqoVar = zzqoVarArr[i];
            zzqs zzqsVar = zzqs.zzb;
            u.b(zzqoVar != zzqsVar);
            zzqo zzqoVar2 = zzqoVarArr[i];
            zzqs zzqsVar2 = zzqs.zzc;
            u.b(zzqoVar2 != zzqsVar2);
            zzqo zzqoVarZzc = zzra.zzc(zzhxVar, zzqoVarArr[i]);
            zzqoVarArr2[i] = zzqoVarZzc;
            u.b(zzqoVarZzc != zzqsVar);
            u.b(zzqoVarArr2[i] != zzqsVar2);
        }
        zzqo zzqoVarZza = zza(zzhxVar, zzqoVarArr2);
        u.k(zzqoVarZza != null);
        return zzqoVarZza;
    }
}
