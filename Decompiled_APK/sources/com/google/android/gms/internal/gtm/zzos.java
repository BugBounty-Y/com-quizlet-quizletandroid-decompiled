package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzos extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 2);
        return new zzqp(Boolean.valueOf(zzjn.zzd(zzqoVarArr[0]).startsWith(zzjn.zzd(zzqoVarArr[1]))));
    }
}
