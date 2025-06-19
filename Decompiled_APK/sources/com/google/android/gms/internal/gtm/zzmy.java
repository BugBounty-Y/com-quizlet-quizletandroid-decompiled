package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzmy extends zzjo {
    private final zzmx zza;

    public zzmy(zzmx zzmxVar) {
        this.zza = zzmxVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        zzqo zzqoVar;
        u.h(zzqoVarArr);
        int length = zzqoVarArr.length;
        u.b(length > 0);
        u.b(zzqoVarArr[0] instanceof zzqz);
        String strZzk = ((zzqz) zzqoVarArr[0]).zzk();
        HashMap map = new HashMap();
        if (length >= 2 && (zzqoVar = zzqoVarArr[1]) != zzqs.zze) {
            u.b(zzqoVar instanceof zzqw);
            for (Map.Entry entry : ((zzqw) zzqoVarArr[1]).zzi().entrySet()) {
                u.k(!(entry.getValue() instanceof zzqx));
                u.k(!zzra.zzi((zzqo) entry.getValue()));
                map.put((String) entry.getKey(), ((zzqo) entry.getValue()).zzc());
            }
        }
        return zzra.zzb(this.zza.zza(strZzk, map));
    }
}
