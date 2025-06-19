package com.google.android.gms.internal.gtm;

import android.text.TextUtils;
import com.google.android.gms.analytics.f;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class zzau extends f {
    private String zza;
    private String zzb;
    private String zzc;
    private String zzd;

    public final String toString() {
        HashMap map = new HashMap();
        map.put("appName", this.zza);
        map.put("appVersion", this.zzb);
        map.put("appId", this.zzc);
        map.put("appInstallerId", this.zzd);
        return f.zza(map);
    }

    public final String zzd() {
        return this.zzc;
    }

    public final String zze() {
        return this.zzd;
    }

    public final String zzf() {
        return this.zza;
    }

    public final String zzg() {
        return this.zzb;
    }

    @Override // com.google.android.gms.analytics.f
    /* renamed from: zzh, reason: merged with bridge method [inline-methods] */
    public final void zzc(zzau zzauVar) {
        if (!TextUtils.isEmpty(this.zza)) {
            zzauVar.zza = this.zza;
        }
        if (!TextUtils.isEmpty(this.zzb)) {
            zzauVar.zzb = this.zzb;
        }
        if (!TextUtils.isEmpty(this.zzc)) {
            zzauVar.zzc = this.zzc;
        }
        if (TextUtils.isEmpty(this.zzd)) {
            return;
        }
        zzauVar.zzd = this.zzd;
    }

    public final void zzi(String str) {
        this.zzc = str;
    }

    public final void zzj(String str) {
        this.zzd = str;
    }

    public final void zzk(String str) {
        this.zza = str;
    }

    public final void zzl(String str) {
        this.zzb = str;
    }
}
