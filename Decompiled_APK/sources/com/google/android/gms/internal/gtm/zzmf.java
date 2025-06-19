package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzmf extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
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
        String strZzd = zzjn.zzd(zzqoVarArr[1]);
        double dZza = Double.POSITIVE_INFINITY;
        if (length == 3 && !Double.isNaN(zzjn.zzb(zzqoVarArr[2]))) {
            dZza = zzjn.zza(zzqoVarArr[2]);
        }
        return new zzqq(Double.valueOf(strZzk.lastIndexOf(strZzd, (int) Math.min(Math.max(dZza, 0.0d), strZzk.length()))));
    }
}
