package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzqi {
    private final Integer zza;
    private final Object zzb;
    private final List zzc = new ArrayList();
    private boolean zzd = false;

    public zzqi(int i, Object obj) {
        this.zza = Integer.valueOf(i);
        this.zzb = obj;
    }

    public final zzqi zza(int i) {
        this.zzc.add(Integer.valueOf(i));
        return this;
    }

    public final zzqi zzb(boolean z) {
        this.zzd = true;
        return this;
    }

    public final zzqk zzc() {
        u.h(this.zza);
        u.h(this.zzb);
        return new zzqk(this.zza, this.zzb, this.zzc, this.zzd, null);
    }
}
