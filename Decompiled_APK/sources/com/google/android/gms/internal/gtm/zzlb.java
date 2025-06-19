package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzlb extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 3);
        u.b(zzqoVarArr[1] instanceof zzqz);
        u.b(zzqoVarArr[2] instanceof zzqv);
        zzqo zzqoVar = zzqoVarArr[0];
        String strZzk = ((zzqz) zzqoVarArr[1]).zzk();
        List listZzk = ((zzqv) zzqoVarArr[2]).zzk();
        if (zzqoVar.zzh(strZzk)) {
            zzqo zzqoVarZzb = zzqoVar.zzb(strZzk);
            if (zzqoVarZzb instanceof zzqr) {
                return ((zzqr) zzqoVarZzb).zzi().zzd(zzhxVar, (zzqo[]) listZzk.toArray(new zzqo[listZzk.size()]));
            }
            throw new IllegalArgumentException(a.B("Apply TypeError: ", strZzk, " is not a function"));
        }
        if (!zzqoVar.zzg(strZzk)) {
            throw new IllegalArgumentException(a.B("Apply TypeError: object has no ", strZzk, " property"));
        }
        zzjm zzjmVarZza = zzqoVar.zza(strZzk);
        listZzk.add(0, zzqoVar);
        return zzjmVarZza.zzd(zzhxVar, (zzqo[]) listZzk.toArray(new zzqo[listZzk.size()]));
    }
}
