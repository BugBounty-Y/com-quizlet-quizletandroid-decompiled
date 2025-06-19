package com.google.android.gms.internal.gtm;

import java.util.AbstractMap;
import java.util.Objects;

/* loaded from: classes2.dex */
final class zzts extends zztl {
    final /* synthetic */ zztt zza;

    public zzts(zztt zzttVar) {
        this.zza = zzttVar;
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ Object get(int i) {
        zztd.zza(i, this.zza.zzc, "index");
        int i2 = i + i;
        Object obj = this.zza.zzb[i2];
        Objects.requireNonNull(obj);
        Object obj2 = this.zza.zzb[i2 + 1];
        Objects.requireNonNull(obj2);
        return new AbstractMap.SimpleImmutableEntry(obj, obj2);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.zza.zzc;
    }
}
