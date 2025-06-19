package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zznw implements zzjm {
    private final Context zza;

    public zznw(Context context) {
        u.h(context);
        this.zza = context;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        zzqo zzqoVar;
        u.b(zzqoVarArr != null);
        String strZzd = null;
        if (zzqoVarArr.length > 0 && (zzqoVar = zzqoVarArr[0]) != zzqs.zze) {
            strZzd = zzjn.zzd(zzra.zzc(zzhxVar, zzqoVar));
        }
        String strZzb = zzhh.zzb(this.zza, strZzd);
        return strZzb != null ? new zzqz(strZzb) : zzqs.zze;
    }
}
