package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzjv extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        int length = zzqoVarArr.length;
        u.b(length > 0 && length <= 3);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        zzqo zzqoVar = length < 2 ? zzqs.zze : zzqoVarArr[1];
        List listZzk = zzqvVar.zzk();
        int size = listZzk.size();
        int iAbs = size - 1;
        if (length == 3) {
            int iZza = (int) zzjn.zza(zzqoVarArr[2]);
            iAbs = iZza < 0 ? size - Math.abs(iZza) : Math.min(iZza, iAbs);
        }
        while (true) {
            if (iAbs < 0) {
                iAbs = -1;
                break;
            }
            if (zzqvVar.zzn(iAbs) && zzjn.zzh(zzqoVar, (zzqo) listZzk.get(iAbs))) {
                break;
            }
            iAbs--;
        }
        return new zzqq(Double.valueOf(iAbs));
    }
}
