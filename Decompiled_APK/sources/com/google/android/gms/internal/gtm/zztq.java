package com.google.android.gms.internal.gtm;

import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
final class zztq extends zzua {
    private final Object zza;
    private boolean zzb;

    public zztq(Object obj) {
        this.zza = obj;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return !this.zzb;
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (this.zzb) {
            throw new NoSuchElementException();
        }
        this.zzb = true;
        return this.zza;
    }
}
