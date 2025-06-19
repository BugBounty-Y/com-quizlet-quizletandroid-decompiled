package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzmj extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) throws NumberFormatException {
        zzqo zzqoVar;
        int length = zzqoVarArr.length;
        u.b(length > 0 && length <= 3);
        u.b(zzqoVarArr[0] instanceof zzqz);
        String strZzk = ((zzqz) zzqoVarArr[0]).zzk();
        double dZza = length < 2 ? 0.0d : zzjn.zza(zzqoVarArr[1]);
        double length2 = strZzk.length();
        if (length == 3 && (zzqoVar = zzqoVarArr[2]) != zzqs.zze) {
            length2 = zzjn.zza(zzqoVar);
        }
        int iMax = (int) (dZza < 0.0d ? Math.max(strZzk.length() + dZza, 0.0d) : Math.min(dZza, strZzk.length()));
        return new zzqz(strZzk.substring(iMax, Math.max(0, ((int) (length2 < 0.0d ? Math.max(strZzk.length() + length2, 0.0d) : Math.min(length2, strZzk.length()))) - iMax) + iMax));
    }
}
