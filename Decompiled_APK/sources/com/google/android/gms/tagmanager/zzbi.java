package com.google.android.gms.tagmanager;

import android.os.Bundle;
import com.google.android.gms.measurement.AppMeasurement;
import java.util.Map;

/* loaded from: classes2.dex */
final class zzbi extends zzcj {
    final /* synthetic */ AppMeasurement zza;

    public zzbi(AppMeasurement appMeasurement) {
        this.zza = appMeasurement;
    }

    @Override // com.google.android.gms.tagmanager.zzck
    public final Map zzb() {
        return this.zza.a.l();
    }

    @Override // com.google.android.gms.tagmanager.zzck
    public final void zzc(String str, String str2, Bundle bundle, long j) {
        this.zza.a.d(str, str2, bundle, j);
    }

    @Override // com.google.android.gms.tagmanager.zzck
    public final void zzd(zzce zzceVar) {
        this.zza.a.a(new zzbh(this, zzceVar));
    }

    @Override // com.google.android.gms.tagmanager.zzck
    public final void zze(zzch zzchVar) {
        this.zza.a.k(new zzbg(this, zzchVar));
    }
}
