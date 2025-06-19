package com.google.android.gms.internal.gtm;

import android.text.TextUtils;
import com.google.android.gms.analytics.f;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class zzav extends f {
    private String zza;
    private String zzb;
    private String zzc;
    private String zzd;
    private String zze;
    private String zzf;
    private String zzg;
    private String zzh;
    private String zzi;
    private String zzj;

    public final String toString() {
        HashMap map = new HashMap();
        map.put("name", this.zza);
        map.put("source", this.zzb);
        map.put("medium", this.zzc);
        map.put("keyword", this.zzd);
        map.put("content", this.zze);
        map.put("id", this.zzf);
        map.put("adNetworkId", this.zzg);
        map.put("gclid", this.zzh);
        map.put("dclid", this.zzi);
        map.put("aclid", this.zzj);
        return f.zza(map);
    }

    @Override // com.google.android.gms.analytics.f
    public final /* bridge */ /* synthetic */ void zzc(f fVar) {
        zzav zzavVar = (zzav) fVar;
        if (!TextUtils.isEmpty(this.zza)) {
            zzavVar.zza = this.zza;
        }
        if (!TextUtils.isEmpty(this.zzb)) {
            zzavVar.zzb = this.zzb;
        }
        if (!TextUtils.isEmpty(this.zzc)) {
            zzavVar.zzc = this.zzc;
        }
        if (!TextUtils.isEmpty(this.zzd)) {
            zzavVar.zzd = this.zzd;
        }
        if (!TextUtils.isEmpty(this.zze)) {
            zzavVar.zze = this.zze;
        }
        if (!TextUtils.isEmpty(this.zzf)) {
            zzavVar.zzf = this.zzf;
        }
        if (!TextUtils.isEmpty(this.zzg)) {
            zzavVar.zzg = this.zzg;
        }
        if (!TextUtils.isEmpty(this.zzh)) {
            zzavVar.zzh = this.zzh;
        }
        if (!TextUtils.isEmpty(this.zzi)) {
            zzavVar.zzi = this.zzi;
        }
        if (TextUtils.isEmpty(this.zzj)) {
            return;
        }
        zzavVar.zzj = this.zzj;
    }

    public final void zzn(String str) {
        this.zzj = str;
    }

    public final void zzo(String str) {
        this.zzg = str;
    }

    public final void zzp(String str) {
        this.zze = str;
    }

    public final void zzq(String str) {
        this.zzi = str;
    }

    public final void zzr(String str) {
        this.zzh = str;
    }

    public final void zzs(String str) {
        this.zzf = str;
    }

    public final void zzt(String str) {
        this.zzd = str;
    }

    public final void zzu(String str) {
        this.zzc = str;
    }

    public final void zzv(String str) {
        this.zza = str;
    }

    public final void zzw(String str) {
        this.zzb = str;
    }
}
