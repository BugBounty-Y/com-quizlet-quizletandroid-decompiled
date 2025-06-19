package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzkc extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        u.b(zzqoVarArr.length == 1);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqs zzqsVar = zzqs.zze;
        List listZzk = ((zzqv) zzqoVarArr[0]).zzk();
        return !listZzk.isEmpty() ? (zzqo) listZzk.remove(0) : zzqsVar;
    }
}
