package com.google.android.gms.internal.ads;

import java.io.Serializable;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.gu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2115gu extends St implements Serializable {
    public final Object a;
    public final List b;

    public C2115gu(Object obj, List list) {
        this.a = obj;
        this.b = list;
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
