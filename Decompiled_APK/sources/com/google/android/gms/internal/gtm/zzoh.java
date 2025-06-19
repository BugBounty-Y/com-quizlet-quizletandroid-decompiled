package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.WindowManager;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzoh implements zzjm {
    private final Context zza;
    private final DisplayMetrics zzb = new DisplayMetrics();

    public zzoh(Context context) {
        this.zza = context;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        ((WindowManager) this.zza.getSystemService("window")).getDefaultDisplay().getMetrics(this.zzb);
        return new zzqz(this.zzb.widthPixels + "x" + this.zzb.heightPixels);
    }
}
