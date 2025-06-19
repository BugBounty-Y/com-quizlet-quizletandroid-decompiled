package com.google.android.gms.internal.gtm;

import android.os.Build;
import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzog implements zzjm {
    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        return new zzqz(a.f(Build.VERSION.SDK_INT, "5.06-"));
    }
}
