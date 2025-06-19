package com.google.android.gms.internal.gtm;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzqf {
    private final List zza = new ArrayList();
    private String zzb;

    public final zzqf zza(zzjl zzjlVar) {
        this.zza.add(zzjlVar);
        return this;
    }

    public final zzqf zzb(String str) {
        this.zzb = str;
        return this;
    }

    public final zzqh zzc() {
        return new zzqh(this.zzb, this.zza, null);
    }
}
