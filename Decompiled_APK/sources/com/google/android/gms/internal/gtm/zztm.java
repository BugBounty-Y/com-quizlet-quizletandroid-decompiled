package com.google.android.gms.internal.gtm;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes2.dex */
final class zztm {
    private final Object zza;
    private final Object zzb;
    private final Object zzc;

    public zztm(Object obj, Object obj2, Object obj3) {
        this.zza = obj;
        this.zzb = obj2;
        this.zzc = obj3;
    }

    public final IllegalArgumentException zza() {
        Object obj = this.zzc;
        Object obj2 = this.zzb;
        Object obj3 = this.zza;
        String strValueOf = String.valueOf(obj3);
        String strValueOf2 = String.valueOf(obj2);
        return new IllegalArgumentException(AbstractC0147y.g(AbstractC0147y.h("Multiple entries with same key: ", strValueOf, SimpleComparison.EQUAL_TO_OPERATION, strValueOf2, " and "), String.valueOf(obj3), SimpleComparison.EQUAL_TO_OPERATION, String.valueOf(obj)));
    }
}
