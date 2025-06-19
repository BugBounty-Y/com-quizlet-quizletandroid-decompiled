package com.google.android.gms.internal.gtm;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
final class zzqt implements Iterator {
    final /* synthetic */ zzqv zza;
    private int zzb = 0;

    public zzqt(zzqv zzqvVar) {
        this.zza = zzqvVar;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        for (int i = this.zzb; i < this.zza.zzc.size(); i++) {
            if (this.zza.zzc.get(i) != null) {
                return true;
            }
        }
        return false;
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Iterator
    /* renamed from: zza, reason: merged with bridge method [inline-methods] */
    public final zzqo next() {
        if (this.zzb >= this.zza.zzc.size()) {
            throw new NoSuchElementException();
        }
        for (int i = this.zzb; i < this.zza.zzc.size(); i++) {
            if (this.zza.zzc.get(i) != null) {
                this.zzb = i;
                int i2 = this.zzb;
                this.zzb = i2 + 1;
                return new zzqq(Double.valueOf(i2));
            }
        }
        throw new NoSuchElementException();
    }
}
