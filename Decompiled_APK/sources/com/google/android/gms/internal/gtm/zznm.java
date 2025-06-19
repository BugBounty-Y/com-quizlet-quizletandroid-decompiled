package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.util.a;
import com.google.android.gms.common.util.b;

/* loaded from: classes2.dex */
public final class zznm implements zzjm {
    private a zza = b.a;

    public final void zza(a aVar) {
        u.h(aVar);
        this.zza = aVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        return new zzqq(Double.valueOf(this.zza.currentTimeMillis()));
    }
}
