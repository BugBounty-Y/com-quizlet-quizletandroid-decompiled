package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.provider.Settings;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzob implements zzjm {
    private final Context zza;

    public zzob(Context context) {
        u.h(context);
        this.zza = context;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        String string = Settings.Secure.getString(this.zza.getContentResolver(), "android_id");
        return string != null ? new zzqz(string) : zzqs.zze;
    }
}
