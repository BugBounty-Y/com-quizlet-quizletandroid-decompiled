package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzlr extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        int length = zzqoVarArr.length;
        u.b(length <= 1);
        return new zzqs(length <= 0 ? zzqs.zze : zzqoVarArr[0]);
    }
}
