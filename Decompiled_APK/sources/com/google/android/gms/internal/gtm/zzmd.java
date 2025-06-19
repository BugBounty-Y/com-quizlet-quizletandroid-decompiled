package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzmd extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length > 0);
        u.b(zzqoVarArr[0] instanceof zzqz);
        StringBuilder sb = new StringBuilder(((zzqz) zzqoVarArr[0]).zzk());
        for (int i = 1; i < zzqoVarArr.length; i++) {
            sb.append(zzjn.zzd(zzqoVarArr[i]));
        }
        return new zzqz(sb.toString());
    }
}
