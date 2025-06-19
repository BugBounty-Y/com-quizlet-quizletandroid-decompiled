package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.stmt.query.SimpleComparison;

/* renamed from: com.google.android.gms.internal.ads.mu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2373mu {
    public final Object a;
    public final Object b;
    public final Object c;

    public C2373mu(Object obj, Object obj2, Object obj3) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
    }

    public final IllegalArgumentException a() {
        Object obj = this.a;
        String strValueOf = String.valueOf(obj);
        String strValueOf2 = String.valueOf(this.b);
        return new IllegalArgumentException(AbstractC0147y.g(AbstractC0147y.h("Multiple entries with same key: ", strValueOf, SimpleComparison.EQUAL_TO_OPERATION, strValueOf2, " and "), String.valueOf(obj), SimpleComparison.EQUAL_TO_OPERATION, String.valueOf(this.c)));
    }
}
