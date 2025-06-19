package com.google.android.gms.internal.gtm;

import android.util.DisplayMetrics;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class zzcw extends zzbr {
    public zzcw(zzbu zzbuVar) {
        super(zzbuVar);
    }

    public final zzaz zza() {
        zzV();
        DisplayMetrics displayMetrics = zzq().a.getResources().getDisplayMetrics();
        zzaz zzazVar = new zzaz();
        zzazVar.zze(zzff.zzd(Locale.getDefault()));
        zzazVar.zza = displayMetrics.widthPixels;
        zzazVar.zzb = displayMetrics.heightPixels;
        return zzazVar;
    }

    public final String zzb() {
        zzV();
        zzaz zzazVarZza = zza();
        return zzazVarZza.zza + "x" + zzazVarZza.zzb;
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
    }
}
