package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzme extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        boolean z;
        int length = zzqoVarArr.length;
        if (length == 2) {
            z = true;
        } else if (length == 3) {
            z = true;
            length = 3;
        } else {
            z = false;
        }
        u.b(z);
        u.b(zzqoVarArr[0] instanceof zzqz);
        String strZzk = ((zzqz) zzqoVarArr[0]).zzk();
        return new zzqq(Double.valueOf(strZzk.indexOf(zzjn.zzd(zzqoVarArr[1]), (int) Math.min(Math.max(length < 3 ? 0.0d : zzjn.zza(zzqoVarArr[2]), 0.0d), strZzk.length()))));
    }
}
