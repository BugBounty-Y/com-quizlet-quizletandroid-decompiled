package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzjy extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        u.b(zzqoVarArr.length > 0);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        int size = zzqvVar.zzk().size();
        zzqvVar.zzm((r4 + size) - 1);
        for (int i = 1; i < zzqoVarArr.length; i++) {
            zzqvVar.zzl(size, zzqoVarArr[i]);
            size++;
        }
        return new zzqq(Double.valueOf(size));
    }
}
