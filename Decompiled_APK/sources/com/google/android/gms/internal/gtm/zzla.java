package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzla extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 1);
        u.b(!(zzqoVarArr[0] instanceof zzqx));
        u.b(!zzra.zzi(zzqoVarArr[0]));
        zzqo zzqoVar = zzqoVarArr[0];
        return new zzqz(zzqoVar == zzqs.zze ? "undefined" : zzqoVar instanceof zzqp ? "boolean" : zzqoVar instanceof zzqq ? "number" : zzqoVar instanceof zzqz ? "string" : zzqoVar instanceof zzqr ? "function" : "object");
    }
}
