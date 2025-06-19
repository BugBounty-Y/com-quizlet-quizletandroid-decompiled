package com.google.common.base;

/* loaded from: classes2.dex */
public abstract class f {
    public abstract boolean a(Object obj, Object obj2);

    public abstract int b(Object obj);

    public final boolean c(Object obj, Object obj2) {
        if (obj == obj2) {
            return true;
        }
        if (obj == null || obj2 == null) {
            return false;
        }
        return a(obj, obj2);
    }
}
