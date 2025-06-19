package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zzkk extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        u.b(zzqoVarArr.length > 0);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        ArrayList arrayList = new ArrayList();
        for (int i = 1; i < zzqoVarArr.length; i++) {
            arrayList.add(zzqoVarArr[i]);
        }
        zzqvVar.zzk().addAll(0, arrayList);
        return new zzqq(Double.valueOf(zzqvVar.zzk().size()));
    }
}
