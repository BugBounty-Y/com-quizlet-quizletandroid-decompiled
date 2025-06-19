package com.google.common.base;

import java.io.Serializable;

/* loaded from: classes2.dex */
public final class d extends f implements Serializable {
    public static final d a = new d();

    private Object readResolve() {
        return a;
    }

    @Override // com.google.common.base.f
    public final boolean a(Object obj, Object obj2) {
        return obj.equals(obj2);
    }

    @Override // com.google.common.base.f
    public final int b(Object obj) {
        return obj.hashCode();
    }
}
