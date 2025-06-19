package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.provider.Settings;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzno implements zzjm {
    private final Context zza;

    public zzno(Context context) {
        this.zza = context;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        String string = Settings.Secure.getString(this.zza.getContentResolver(), "android_id");
        if (string == null) {
            string = "";
        }
        return new zzqz(string);
    }
}
