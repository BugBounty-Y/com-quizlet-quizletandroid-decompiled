package androidx.navigation.internal;

import androidx.collection.W;
import androidx.collection.r;
import androidx.navigation.B;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public final class n implements Iterator, kotlin.jvm.internal.markers.a {
    public int a = -1;
    public boolean b;
    public final /* synthetic */ androidx.camera.camera2.internal.concurrent.a c;

    public n(androidx.camera.camera2.internal.concurrent.a aVar) {
        this.c = aVar;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a + 1 < ((W) this.c.d).g();
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        this.b = true;
        W w = (W) this.c.d;
        int i = this.a + 1;
        this.a = i;
        return (B) w.h(i);
    }

    @Override // java.util.Iterator
    public final void remove() {
        if (!this.b) {
            throw new IllegalStateException("You must call next() before you can remove an element");
        }
        W w = (W) this.c.d;
        ((B) w.h(this.a)).c = null;
        int i = this.a;
        Object[] objArr = w.c;
        Object obj = objArr[i];
        Object obj2 = r.b;
        if (obj != obj2) {
            objArr[i] = obj2;
            w.a = true;
        }
        this.a = i - 1;
        this.b = false;
    }
}
