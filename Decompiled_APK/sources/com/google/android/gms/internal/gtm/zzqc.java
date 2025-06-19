package com.google.android.gms.internal.gtm;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzqc {
    private final List zza = new ArrayList();
    private final List zzb = new ArrayList();
    private final List zzc = new ArrayList();
    private final List zzd = new ArrayList();

    public final zzqc zza(zzqb zzqbVar) {
        this.zzc.add(zzqbVar);
        return this;
    }

    public final zzqc zzb(zzqb zzqbVar) {
        this.zzb.add(zzqbVar);
        return this;
    }

    public final zzqc zzc(zzqb zzqbVar) {
        this.zza.add(zzqbVar);
        return this;
    }

    public final zzqc zzd(zzqb zzqbVar) {
        this.zzd.add(zzqbVar);
        return this;
    }

    public final zzqe zze() {
        return new zzqe(this.zza, this.zzb, this.zzc, this.zzd, null);
    }
}
