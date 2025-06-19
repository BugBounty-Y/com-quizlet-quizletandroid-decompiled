package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.ads.Rt;
import java.io.Serializable;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3260t extends AbstractC3181k implements Serializable {
    public final Object a;
    public final Rt b;

    public C3260t(Object obj, Rt rt) {
        this.a = obj;
        this.b = rt;
    }

    @Override // java.util.Map.Entry
    public final Object getKey() {
        return this.a;
    }

    @Override // java.util.Map.Entry
    public final Object getValue() {
        return this.b;
    }

    @Override // java.util.Map.Entry
    public final Object setValue(Object obj) {
        throw new UnsupportedOperationException();
    }
}
