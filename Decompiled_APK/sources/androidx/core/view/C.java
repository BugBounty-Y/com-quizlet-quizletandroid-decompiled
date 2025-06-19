package androidx.core.view;

import android.view.View;
import android.view.ViewGroup;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.CollectionsKt;

/* loaded from: classes.dex */
public final class C implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public Iterator b;
    public final Object c;

    public C(io.ktor.util.f fVar) {
        this.a = 1;
        this.c = fVar;
        this.b = fVar.a.iterator();
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
                Object next = this.b.next();
                View view = (View) next;
                ViewGroup viewGroup = view instanceof ViewGroup ? (ViewGroup) view : null;
                Y y = viewGroup != null ? new Y(viewGroup) : null;
                ArrayList arrayList = (ArrayList) this.c;
                if (y == null || !y.hasNext()) {
                    while (!this.b.hasNext() && !arrayList.isEmpty()) {
                        this.b = (Iterator) CollectionsKt.U(arrayList);
                        kotlin.collections.G.A(arrayList);
                    }
                } else {
                    arrayList.add(this.b);
                    this.b = y;
                }
                return next;
            case 1:
                return ((io.ktor.util.f) this.c).b.invoke(this.b.next());
            default:
                return ((kotlin.sequences.t) this.c).c.invoke(this.b.next());
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 1:
                this.b.remove();
                return;
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public C(Y y) {
        this.a = 0;
        this.c = new ArrayList();
        this.b = y;
    }

    public C(kotlin.sequences.t tVar) {
        this.a = 2;
        this.c = tVar;
        this.b = tVar.b.iterator();
    }
}
