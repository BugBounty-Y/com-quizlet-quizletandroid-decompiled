package androidx.compose.runtime.snapshots;

import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.Map;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class y implements Iterator, kotlin.jvm.internal.markers.a {
    public final t a;
    public final Iterator b;
    public int c;
    public Map.Entry d;
    public Map.Entry e;
    public final /* synthetic */ int f;

    public y(t tVar, Iterator it2, int i) {
        this.f = i;
        this.a = tVar;
        this.b = it2;
        this.c = tVar.e().d;
        a();
    }

    public final void a() {
        this.d = this.e;
        Iterator it2 = this.b;
        this.e = it2.hasNext() ? (Map.Entry) it2.next() : null;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.e != null;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.f) {
            case 0:
                a();
                if (this.d != null) {
                    return new x(this);
                }
                throw new IllegalStateException();
            case 1:
                Map.Entry entry = this.e;
                if (entry == null) {
                    throw new IllegalStateException();
                }
                a();
                return entry.getKey();
            default:
                Map.Entry entry2 = this.e;
                if (entry2 == null) {
                    throw new IllegalStateException();
                }
                a();
                return entry2.getValue();
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        t tVar = this.a;
        if (tVar.e().d != this.c) {
            throw new ConcurrentModificationException();
        }
        Map.Entry entry = this.d;
        if (entry == null) {
            throw new IllegalStateException();
        }
        tVar.remove(entry.getKey());
        this.d = null;
        Unit unit = Unit.a;
        this.c = tVar.e().d;
    }
}
