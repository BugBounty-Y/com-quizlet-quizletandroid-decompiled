package com.google.android.gms.internal.gtm;

import java.util.Iterator;

/* loaded from: classes2.dex */
final class zzqu implements Iterator {
    final /* synthetic */ Iterator zza;
    final /* synthetic */ Iterator zzb;

    public zzqu(zzqv zzqvVar, Iterator it2, Iterator it3) {
        this.zza = it2;
        this.zzb = it3;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.zza.hasNext() || this.zzb.hasNext();
    }

    @Override // java.util.Iterator
    public final /* bridge */ /* synthetic */ Object next() {
        return this.zza.hasNext() ? ((zzqt) this.zza).next() : (zzqo) this.zzb.next();
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }
}
