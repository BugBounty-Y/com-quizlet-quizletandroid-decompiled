package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class zzmq extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr.length == 1);
        u.b(zzqoVarArr[0] instanceof zzqz);
        return new zzqz(((zzqz) zzqoVarArr[0]).zzk().toUpperCase(Locale.ENGLISH));
    }
}
