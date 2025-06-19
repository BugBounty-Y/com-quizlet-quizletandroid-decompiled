package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.io.UnsupportedEncodingException;

/* loaded from: classes2.dex */
public final class zzmt extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        zzqo zzqoVar;
        if (zzqoVarArr.length > 0) {
            zzqoVar = zzqoVarArr[0];
            u.h(zzqoVar);
        } else {
            zzqoVar = zzqs.zze;
        }
        try {
            return new zzqz(zzms.zzb(zzjn.zzd(zzqoVar), ""));
        } catch (UnsupportedEncodingException unused) {
            return zzqs.zze;
        }
    }
}
