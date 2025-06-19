package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class zzle extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 1);
        u.b(zzqoVarArr[0] instanceof zzqv);
        Iterator it2 = ((zzqv) zzqoVarArr[0]).zzk().iterator();
        while (it2.hasNext()) {
            zzqo zzqoVarZzc = zzra.zzc(zzhxVar, (zzqo) it2.next());
            if ((zzqoVarZzc instanceof zzqs) && (zzqoVarZzc == zzqs.zzb || zzqoVarZzc == zzqs.zzc || ((zzqs) zzqoVarZzc).zzj())) {
                return zzqoVarZzc;
            }
        }
        return zzqs.zze;
    }
}
