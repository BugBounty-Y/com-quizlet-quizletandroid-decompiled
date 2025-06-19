package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Collections;

/* loaded from: classes2.dex */
public final class zzki extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        zzqr zzqrVar;
        u.h(zzqoVarArr);
        int length = zzqoVarArr.length;
        if (length == 1) {
            z = true;
        } else if (length == 2) {
            length = 2;
            z = true;
        } else {
            z = false;
        }
        u.b(z);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        if (length == 2) {
            u.b(zzqoVarArr[1] instanceof zzqr);
            zzqrVar = (zzqr) zzqoVarArr[1];
        } else {
            zzqrVar = new zzqr(new zzkg(null));
        }
        Collections.sort(zzqvVar.zzk(), new zzkf(this, zzqrVar, zzhxVar));
        return zzqoVarArr[0];
    }
}
