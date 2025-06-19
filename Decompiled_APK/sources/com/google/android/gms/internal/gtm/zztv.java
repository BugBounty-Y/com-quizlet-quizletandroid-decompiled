package com.google.android.gms.internal.gtm;

import java.util.Objects;

/* loaded from: classes2.dex */
final class zztv extends zztl {
    private final transient Object[] zza;
    private final transient int zzb;
    private final transient int zzc = 6;

    public zztv(Object[] objArr, int i, int i2) {
        this.zza = objArr;
        this.zzb = i;
    }

    @Override // java.util.List
    public final Object get(int i) {
        zztd.zza(i, this.zzc, "index");
        Object obj = this.zza[i + i + this.zzb];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.zzc;
    }
}
