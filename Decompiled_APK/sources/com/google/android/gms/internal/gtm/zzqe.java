package com.google.android.gms.internal.gtm;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzqe {
    private final List zza;
    private final List zzb;
    private final List zzc;
    private final List zzd;

    public /* synthetic */ zzqe(List list, List list2, List list3, List list4, zzqd zzqdVar) {
        this.zza = Collections.unmodifiableList(list);
        this.zzb = Collections.unmodifiableList(list2);
        this.zzc = Collections.unmodifiableList(list3);
        this.zzd = Collections.unmodifiableList(list4);
    }

    public final String toString() {
        List list = this.zzd;
        List list2 = this.zzc;
        List list3 = this.zzb;
        String strValueOf = String.valueOf(this.zza);
        String strValueOf2 = String.valueOf(list3);
        return AbstractC0147y.g(AbstractC0147y.h("Positive predicates: ", strValueOf, "  Negative predicates: ", strValueOf2, "  Add tags: "), String.valueOf(list2), "  Remove tags: ", String.valueOf(list));
    }

    public final List zza() {
        return this.zzc;
    }

    public final List zzb() {
        return this.zzb;
    }

    public final List zzc() {
        return this.zza;
    }

    public final List zzd() {
        return this.zzd;
    }
}
