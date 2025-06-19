package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzlc extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 2);
        u.b(zzqoVarArr[0] instanceof zzqz);
        String strZzk = ((zzqz) zzqoVarArr[0]).zzk();
        if (!zzhxVar.zzf(strZzk)) {
            throw new IllegalStateException("Attempting to assign to undefined variable ".concat(String.valueOf(strZzk)));
        }
        zzhxVar.zze(strZzk, zzqoVarArr[1]);
        return zzqoVarArr[1];
    }
}
