package androidx.arch.core.internal;

import java.util.HashMap;

/* loaded from: classes.dex */
public final class a extends f {
    public final HashMap e = new HashMap();

    @Override // androidx.arch.core.internal.f
    public final c a(Object obj) {
        return (c) this.e.get(obj);
    }

    @Override // androidx.arch.core.internal.f
    public final Object b(Object obj) {
        Object objB = super.b(obj);
        this.e.remove(obj);
        return objB;
    }
}
