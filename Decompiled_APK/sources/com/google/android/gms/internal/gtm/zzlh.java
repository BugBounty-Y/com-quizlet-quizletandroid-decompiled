package com.google.android.gms.internal.gtm;

import java.util.HashMap;

/* loaded from: classes2.dex */
public final class zzlh extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        HashMap map = new HashMap();
        for (int i = 0; i < zzqoVarArr.length - 1; i += 2) {
            String strZzd = zzjn.zzd(zzqoVarArr[i]);
            zzqo zzqoVar = zzqoVarArr[i + 1];
            if ((zzqoVar instanceof zzqs) && zzqoVar != zzqs.zzd && zzqoVar != zzqs.zze) {
                throw new IllegalStateException("Illegal InternalType found in CreateObject.");
            }
            map.put(strZzd, zzqoVar);
        }
        return new zzqw(map);
    }
}
