package com.google.common.base;

import java.io.Serializable;

/* loaded from: classes2.dex */
public final class e extends f implements Serializable {
    public static final e a = new e();

    private Object readResolve() {
        return a;
    }

    @Override // com.google.common.base.f
    public final boolean a(Object obj, Object obj2) {
        return false;
    }

    @Override // com.google.common.base.f
    public final int b(Object obj) {
        return System.identityHashCode(obj);
    }
}
