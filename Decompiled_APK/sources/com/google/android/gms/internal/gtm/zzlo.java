package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzlo extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        int length = zzqoVarArr.length;
        if (length == 2) {
            z = true;
        } else if (length == 3) {
            length = 3;
            z = true;
        } else {
            z = false;
        }
        u.b(z);
        u.b(zzqoVarArr[1] instanceof zzqv);
        if (length == 3) {
            u.b(zzqoVarArr[2] instanceof zzqv);
        }
        List arrayList = new ArrayList();
        if (zzjn.zzg(zzqoVarArr[0])) {
            arrayList = ((zzqv) zzqoVarArr[1]).zzk();
        } else if (length > 2) {
            arrayList = ((zzqv) zzqoVarArr[2]).zzk();
        }
        zzqs zzqsVarZzf = zzra.zzf(zzhxVar, arrayList);
        return zzra.zzi(zzqsVarZzf) ? zzqsVarZzf : zzqs.zze;
    }
}
