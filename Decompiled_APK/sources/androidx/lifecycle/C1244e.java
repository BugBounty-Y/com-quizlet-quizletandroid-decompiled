package androidx.lifecycle;

import java.lang.reflect.Method;

/* renamed from: androidx.lifecycle.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1244e {
    public final int a;
    public final Method b;

    public C1244e(Method method, int i) throws SecurityException {
        this.a = i;
        this.b = method;
        method.setAccessible(true);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1244e)) {
            return false;
        }
        C1244e c1244e = (C1244e) obj;
        return this.a == c1244e.a && this.b.getName().equals(c1244e.b.getName());
    }

    public final int hashCode() {
        return this.b.getName().hashCode() + (this.a * 31);
    }
}
