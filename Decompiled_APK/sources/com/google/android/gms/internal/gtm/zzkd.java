package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class zzkd extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        u.h(zzqoVarArr);
        int length = zzqoVarArr.length;
        if (length == 2) {
            z = true;
        } else if (length == 3) {
            z = true;
            length = 3;
        } else {
            z = false;
        }
        u.b(z);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        int iZza = (int) zzjn.zza(zzqoVarArr[1]);
        int iMax = iZza < 0 ? Math.max(zzqvVar.zzk().size() + iZza, 0) : Math.min(iZza, zzqvVar.zzk().size());
        int size = zzqvVar.zzk().size();
        if (length == 3) {
            int iZza2 = (int) zzjn.zza(zzqoVarArr[2]);
            size = iZza2 < 0 ? Math.max(zzqvVar.zzk().size() + iZza2, 0) : Math.min(iZza2, zzqvVar.zzk().size());
        }
        return new zzqv(new ArrayList(zzqvVar.zzk().subList(iMax, Math.max(iMax, size))));
    }
}
