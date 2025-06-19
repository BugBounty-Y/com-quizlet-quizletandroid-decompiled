package com.google.android.gms.internal.gtm;

import java.util.Objects;

/* loaded from: classes2.dex */
final class zztr extends zztl {
    static final zztl zza = new zztr(new Object[0], 0);
    final transient Object[] zzb;
    private final transient int zzc;

    public zztr(Object[] objArr, int i) {
        this.zzb = objArr;
        this.zzc = i;
    }

    @Override // java.util.List
    public final Object get(int i) {
        zztd.zza(i, this.zzc, "index");
        Object obj = this.zzb[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.zzc;
    }

    @Override // com.google.android.gms.internal.gtm.zztl, com.google.android.gms.internal.gtm.zzti
    public final int zza(Object[] objArr, int i) {
        System.arraycopy(this.zzb, 0, objArr, 0, this.zzc);
        return this.zzc;
    }

    @Override // com.google.android.gms.internal.gtm.zzti
    public final int zzb() {
        return this.zzc;
    }

    @Override // com.google.android.gms.internal.gtm.zzti
    public final int zzc() {
        return 0;
    }

    @Override // com.google.android.gms.internal.gtm.zzti
    public final Object[] zze() {
        return this.zzb;
    }
}
