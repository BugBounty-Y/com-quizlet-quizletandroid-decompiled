package kotlin.collections;

import java.util.Iterator;

/* loaded from: classes3.dex */
public abstract class P implements Iterator, kotlin.jvm.internal.markers.a {
    @Override // java.util.Iterator
    public final /* bridge */ /* synthetic */ Object next() {
        return Integer.valueOf(nextInt());
    }

    public abstract int nextInt();

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
