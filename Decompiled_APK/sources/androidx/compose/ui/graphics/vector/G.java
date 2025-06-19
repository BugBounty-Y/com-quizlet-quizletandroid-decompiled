package androidx.compose.ui.graphics.vector;

import java.util.Iterator;
import java.util.Map;

/* loaded from: classes.dex */
public final class G implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public final Iterator b;

    public /* synthetic */ G(Iterator it2, int i) {
        this.a = i;
        this.b = it2;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
        }
        return this.b.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                return (J) this.b.next();
            case 1:
                return ((Map.Entry) this.b.next()).getKey();
            default:
                return ((Map.Entry) this.b.next()).getValue();
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public G(H h) {
        this.a = 0;
        this.b = h.j.iterator();
    }
}
