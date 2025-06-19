package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zznc implements zzjm {
    private final zzgc zza;

    public zznc(Context context) {
        this.zza = zzgc.zzb(context);
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        String strZzc = this.zza.zzc();
        return strZzc == null ? zzqs.zze : new zzqz(strZzc);
    }
}
