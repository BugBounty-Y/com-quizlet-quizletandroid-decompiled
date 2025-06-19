package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class zzjp extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        u.b(zzqoVarArr.length > 0);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        ArrayList arrayList = new ArrayList();
        Iterator it2 = zzqvVar.zzk().iterator();
        while (it2.hasNext()) {
            arrayList.add((zzqo) it2.next());
        }
        for (int i = 1; i < zzqoVarArr.length; i++) {
            zzqo zzqoVar = zzqoVarArr[i];
            if (zzqoVar instanceof zzqv) {
                Iterator it3 = ((zzqv) zzqoVar).zzk().iterator();
                while (it3.hasNext()) {
                    arrayList.add((zzqo) it3.next());
                }
            } else {
                arrayList.add(zzqoVar);
            }
        }
        return new zzqv(arrayList);
    }
}
