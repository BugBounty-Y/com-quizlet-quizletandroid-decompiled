package kotlin.collections;

import java.util.Iterator;

/* renamed from: kotlin.collections.z, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4934z implements Iterator, kotlin.jvm.internal.markers.a {
    public abstract char a();

    @Override // java.util.Iterator
    public final /* bridge */ /* synthetic */ Object next() {
        return Character.valueOf(a());
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
