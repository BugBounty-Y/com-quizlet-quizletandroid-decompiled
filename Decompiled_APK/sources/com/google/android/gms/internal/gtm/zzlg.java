package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zzlg extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        ArrayList arrayList = new ArrayList();
        for (zzqo zzqoVar : zzqoVarArr) {
            boolean z = true;
            if ((zzqoVar instanceof zzqs) && zzqoVar != zzqs.zze && zzqoVar != zzqs.zzd) {
                z = false;
            }
            u.b(z);
            arrayList.add(zzqoVar);
        }
        return new zzqv(arrayList);
    }
}
