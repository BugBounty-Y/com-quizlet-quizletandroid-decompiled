package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zzlq implements zzjm {
    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        ArrayList arrayList = new ArrayList(zzqoVarArr.length);
        for (zzqo zzqoVar : zzqoVarArr) {
            arrayList.add(zzqoVar);
        }
        return new zzqv(arrayList);
    }
}
