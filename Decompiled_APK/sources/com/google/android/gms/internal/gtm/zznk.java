package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zznk implements zzjm {
    private final zzqo zza;

    public zznk(zzqo zzqoVar) {
        u.h(zzqoVar);
        this.zza = zzqoVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        return this.zza;
    }
}
