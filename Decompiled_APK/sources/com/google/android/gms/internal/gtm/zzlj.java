package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzlj extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.h(zzqoVarArr);
        u.b(zzqoVarArr.length == 3);
        u.b(zzqoVarArr[0] instanceof zzqz);
        String strZzk = ((zzqz) zzqoVarArr[0]).zzk();
        u.b(zzhxVar.zzf(strZzk));
        zzqo zzqoVar = zzqoVarArr[1];
        u.h(zzqoVar);
        zzqo zzqoVar2 = zzqoVarArr[2];
        u.b(zzqoVar2 instanceof zzqv);
        List listZzk = ((zzqv) zzqoVar2).zzk();
        Iterator itZze = zzqoVar.zze();
        while (itZze.hasNext()) {
            zzhxVar.zze(strZzk, (zzqo) itZze.next());
            zzqs zzqsVarZzf = zzra.zzf(zzhxVar, listZzk);
            if (zzqsVarZzf == zzqs.zzb) {
                break;
            }
            if (zzqsVarZzf.zzj()) {
                return zzqsVarZzf;
            }
        }
        return zzqs.zze;
    }
}
