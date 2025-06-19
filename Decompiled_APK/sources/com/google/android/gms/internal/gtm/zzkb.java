package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Collections;

/* loaded from: classes2.dex */
public final class zzkb extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        u.b(zzqoVarArr.length == 1);
        u.b(zzqoVarArr[0] instanceof zzqv);
        Collections.reverse(((zzqv) zzqoVarArr[0]).zzk());
        return zzqoVarArr[0];
    }
}
