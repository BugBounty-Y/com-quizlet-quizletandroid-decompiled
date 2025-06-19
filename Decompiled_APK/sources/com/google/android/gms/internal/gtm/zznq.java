package com.google.android.gms.internal.gtm;

import android.os.Build;
import android.support.v4.media.session.a;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zznq implements zzjm {
    private final String zza = Build.MANUFACTURER;
    private final String zzb = Build.MODEL;

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        String str = this.zza;
        String strL = this.zzb;
        if (!strL.startsWith(str) && !str.equals(DtbDeviceDataRetriever.ORIENTATION_UNKNOWN)) {
            strL = a.l(str, " ", strL);
        }
        return new zzqz(strL);
    }
}
