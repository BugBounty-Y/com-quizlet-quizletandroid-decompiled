package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzml extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        zzqo zzqoVar;
        int length = zzqoVarArr.length;
        u.b(length > 0 && length <= 3);
        u.b(zzqoVarArr[0] instanceof zzqz);
        String strZzk = ((zzqz) zzqoVarArr[0]).zzk();
        int iZza = (int) zzjn.zza(length < 2 ? zzqs.zze : zzqoVarArr[1]);
        int length2 = strZzk.length();
        if (length == 3 && (zzqoVar = zzqoVarArr[2]) != zzqs.zze) {
            length2 = (int) zzjn.zza(zzra.zzc(zzhxVar, zzqoVar));
        }
        int iMin = Math.min(Math.max(iZza, 0), strZzk.length());
        int iMin2 = Math.min(Math.max(length2, 0), strZzk.length());
        return new zzqz(strZzk.substring(Math.min(iMin, iMin2), Math.max(iMin, iMin2)));
    }
}
