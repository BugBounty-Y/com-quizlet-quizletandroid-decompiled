package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzoa extends zzjo {
    private final zzht zza;

    public zzoa(zzht zzhtVar) {
        this.zza = zzhtVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        int length = zzqoVarArr.length;
        u.b(length > 0);
        Object obj = this.zza.zza().zzd().get(zzjn.zzd(zzqoVarArr[0]));
        Object obj2 = obj;
        obj2 = obj;
        if (obj == null && length > 1) {
            obj2 = zzqoVarArr[1];
        }
        return zzra.zzb(obj2);
    }
}
