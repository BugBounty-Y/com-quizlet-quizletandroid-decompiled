package com.google.android.gms.internal.gtm;

import android.text.TextUtils;
import com.google.android.gms.analytics.f;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class zzaz extends f {
    public int zza;
    public int zzb;
    private String zzc;

    public final String toString() {
        HashMap map = new HashMap();
        map.put("language", this.zzc);
        map.put("screenColors", 0);
        map.put("screenWidth", Integer.valueOf(this.zza));
        map.put("screenHeight", Integer.valueOf(this.zzb));
        map.put("viewportWidth", 0);
        map.put("viewportHeight", 0);
        return f.zza(map);
    }

    @Override // com.google.android.gms.analytics.f
    public final /* bridge */ /* synthetic */ void zzc(f fVar) {
        zzaz zzazVar = (zzaz) fVar;
        int i = this.zza;
        if (i != 0) {
            zzazVar.zza = i;
        }
        int i2 = this.zzb;
        if (i2 != 0) {
            zzazVar.zzb = i2;
        }
        if (TextUtils.isEmpty(this.zzc)) {
            return;
        }
        zzazVar.zzc = this.zzc;
    }

    public final String zzd() {
        return this.zzc;
    }

    public final void zze(String str) {
        this.zzc = str;
    }
}
