package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zzkj extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        u.b(zzqoVarArr.length >= 3);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        int iZza = (int) zzjn.zza(zzqoVarArr[1]);
        int iMax = iZza < 0 ? Math.max(zzqvVar.zzk().size() + iZza, 0) : Math.min(iZza, zzqvVar.zzk().size());
        int iMin = Math.min(Math.max((int) zzjn.zza(zzqoVarArr[2]), 0), zzqvVar.zzk().size() - iMax) + iMax;
        ArrayList arrayList = new ArrayList(zzqvVar.zzk().subList(iMax, iMin));
        zzqvVar.zzk().subList(iMax, iMin).clear();
        ArrayList arrayList2 = new ArrayList();
        for (int i = 3; i < zzqoVarArr.length; i++) {
            arrayList2.add(zzqoVarArr[i]);
        }
        zzqvVar.zzk().addAll(iMax, arrayList2);
        return new zzqv(arrayList);
    }
}
