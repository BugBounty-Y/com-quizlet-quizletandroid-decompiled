package androidx.compose.foundation.layout;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;

/* loaded from: classes.dex */
public final class F implements Iterator, kotlin.jvm.internal.markers.a {
    public final int a;
    public final C0389h0 b;
    public final ArrayList c = new ArrayList();
    public int d;
    public int e;

    public F(int i, C0389h0 c0389h0) {
        this.a = i;
        this.b = c0389h0;
    }

    public final androidx.compose.ui.layout.J a(C0383e0 c0383e0) {
        int i = this.e;
        ArrayList arrayList = this.c;
        if (i < arrayList.size()) {
            androidx.compose.ui.layout.J j = (androidx.compose.ui.layout.J) arrayList.get(this.e);
            this.e++;
            return j;
        }
        int i2 = this.d;
        if (i2 >= this.a) {
            throw new IndexOutOfBoundsException("No item returned at index call. Index: " + this.d);
        }
        List list = (List) this.b.invoke(Integer.valueOf(i2), c0383e0);
        this.d++;
        if (list.isEmpty()) {
            float f = 0;
            return a(new C0383e0(f, f));
        }
        androidx.compose.ui.layout.J j2 = (androidx.compose.ui.layout.J) CollectionsKt.L(list);
        arrayList.addAll(list);
        this.e++;
        return j2;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.e < this.c.size() || this.d < this.a;
    }

    @Override // java.util.Iterator
    public final Object next() {
        float f = 0;
        return a(new C0383e0(f, f));
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
