package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzlv implements zzjm {
    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length > 0);
        for (zzqo zzqoVar : zzqoVarArr) {
            u.h(zzqoVar);
            u.b(zzqoVar instanceof zzqz);
            zzhxVar.zzc(((zzqz) zzqoVar).zzk(), zzqs.zze);
        }
        return zzqs.zze;
    }
}
