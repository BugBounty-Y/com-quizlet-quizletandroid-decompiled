package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzjz extends zzjo {
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
        if (length == 3) {
            zzqoVarZzi = zzqoVarArr[2];
            i = 0;
        } else {
            u.k(size > 0);
            zzqoVarZzi = zzqvVar.zzi(0);
            int i2 = 0;
            while (true) {
                if (i2 >= size) {
                    i = 1;
                    break;
                }
                i = i2 + 1;
                if (zzqvVar.zzn(i2)) {
                    zzqoVarZzi = zzqvVar.zzi(i2);
                    break;
                }
                i2 = i;
            }
            u.k(i2 < size);
        }
        while (i < size && i < zzqvVar.zzk().size()) {
            if (zzqvVar.zzn(i)) {
                zzqoVarZzi = zzqrVar.zzi().zzd(zzhxVar, zzqoVarZzi, (zzqo) listZzk.get(i), new zzqq(Double.valueOf(i)), zzqvVar);
            }
            i++;
        }
        return zzqoVarZzi;
    }
}
