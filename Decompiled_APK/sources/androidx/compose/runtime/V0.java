package androidx.compose.runtime;

import java.util.Iterator;

/* loaded from: classes.dex */
public final class V0 implements Iterable, kotlin.jvm.internal.markers.a {
    public final A0 a;
    public final int b;
    public final C0776c c;

    public V0(A0 a0, int i, M m, C0776c c0776c) {
        this.a = a0;
        this.b = i;
        this.c = c0776c;
        m.getClass();
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new L(this.a, this.b, null, this.c);
    }
}
