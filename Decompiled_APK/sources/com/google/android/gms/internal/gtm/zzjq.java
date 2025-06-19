package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzjq extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        u.b(zzqoVarArr.length == 2);
        u.b(zzqoVarArr[0] instanceof zzqv);
        u.b(zzqoVarArr[1] instanceof zzqr);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        zzqr zzqrVar = (zzqr) zzqoVarArr[1];
        List listZzk = zzqvVar.zzk();
        int size = listZzk.size();
        boolean zZzg = true;
        for (int i = 0; zZzg && i < size && i < zzqvVar.zzk().size(); i++) {
            if (zzqvVar.zzn(i)) {
                zZzg = zzjn.zzg(zzqrVar.zzi().zzd(zzhxVar, (zzqo) listZzk.get(i), new zzqq(Double.valueOf(i)), zzqvVar));
            }
        }
        return new zzqp(Boolean.valueOf(zZzg));
    }
}
