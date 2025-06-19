package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zznd implements zzjm {
    private final zzgc zza;

    public zznd(Context context) {
        this.zza = zzgc.zzb(context);
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        return new zzqp(Boolean.valueOf(!this.zza.zzf()));
    }
}
