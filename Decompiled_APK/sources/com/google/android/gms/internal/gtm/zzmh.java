package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzmh extends zzjo {
    @Override // com.google.android.gms.internal.gtm.zzjo
    public final zzqo zza(zzhx zzhxVar, zzqo... zzqoVarArr) {
        int length = zzqoVarArr.length;
        u.b(length > 0 && length <= 3);
        u.b(zzqoVarArr[0] instanceof zzqz);
        String strZzk = ((zzqz) zzqoVarArr[0]).zzk();
        if (length == 1) {
            return new zzqz(strZzk);
        }
        String strZzd = zzjn.zzd(zzqoVarArr[1]);
        zzqo zzqoVarZzd = length < 3 ? zzqs.zze : zzqoVarArr[2];
        int iIndexOf = strZzk.indexOf(strZzd);
        if (iIndexOf == -1) {
            return new zzqz(strZzk);
        }
        if (zzqoVarZzd instanceof zzqr) {
            zzqoVarZzd = ((zzqr) zzqoVarZzd).zzi().zzd(zzhxVar, new zzqz(strZzd), new zzqq(Double.valueOf(iIndexOf)), new zzqz(strZzk));
        }
        return new zzqz(a.l(strZzk.substring(0, iIndexOf), zzjn.zzd(zzqoVarZzd), strZzk.substring(strZzd.length() + iIndexOf)));
    }
}
