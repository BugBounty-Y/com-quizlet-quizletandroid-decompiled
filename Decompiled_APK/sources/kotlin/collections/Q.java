package kotlin.collections;

import java.util.Iterator;

/* loaded from: classes3.dex */
public abstract class Q implements Iterator, kotlin.jvm.internal.markers.a {
    public abstract long a();

    @Override // java.util.Iterator
    public final /* bridge */ /* synthetic */ Object next() {
        return Long.valueOf(a());
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
