package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzjt extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        int length = zzqoVarArr.length;
        int iMax = 0;
        u.b(length > 0 && length <= 3);
        u.b(zzqoVarArr[0] instanceof zzqv);
        zzqv zzqvVar = (zzqv) zzqoVarArr[0];
        zzqo zzqoVar = length < 2 ? zzqs.zze : zzqoVarArr[1];
        zzqo zzqoVar2 = length < 3 ? zzqs.zze : zzqoVarArr[2];
        List listZzk = zzqvVar.zzk();
        int size = listZzk.size();
        if (zzqoVar2 != zzqs.zze) {
            int iZza = (int) zzjn.zza(zzqoVar2);
            iMax = iZza < 0 ? Math.max(size - Math.abs(iZza), 0) : iZza;
        }
        while (true) {
            if (iMax >= size) {
                iMax = -1;
                break;
            }
            if (zzqvVar.zzn(iMax) && zzjn.zzh(zzqoVar, (zzqo) listZzk.get(iMax))) {
                break;
            }
            iMax++;
        }
        return new zzqq(Double.valueOf(iMax));
    }
}
