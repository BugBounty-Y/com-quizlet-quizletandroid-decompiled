package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzka extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        zzqo zzqoVarZzi;
        int i;
        u.h(zzqoVarArr);
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
        u.b(zzqoVarArr[0] instanceof zzqv);
        u.b(zzqoVarArr[1] instanceof zzqr);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        zzqr zzqrVar = (zzqr) zzqoVarArr[1];
        List listZzk = zzqvVar.zzk();
        int size = listZzk.size();
        int i2 = size - 1;
        if (length == 3) {
            zzqoVarZzi = zzqoVarArr[2];
        } else {
            u.k(size > 0);
            zzqoVarZzi = zzqvVar.zzi(i2);
            int i3 = size - 2;
            while (true) {
                if (i2 < 0) {
                    i = i3;
                    break;
                }
                i = i2 - 1;
                if (zzqvVar.zzn(i2)) {
                    zzqoVarZzi = zzqvVar.zzi(i2);
                    break;
                }
                i2 = i;
            }
            u.k(i2 >= 0);
            i2 = i;
        }
        while (i2 >= 0) {
            if (zzqvVar.zzn(i2)) {
                zzqoVarZzi = zzqrVar.zzi().zzd(zzhxVar, zzqoVarZzi, (zzqo) listZzk.get(i2), new zzqq(Double.valueOf(i2)), zzqvVar);
            }
            i2--;
        }
        return zzqoVarZzi;
    }
}
