package androidx.collection;

import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.collection.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0204b implements Iterator, kotlin.jvm.internal.markers.a {
    public int a;
    public int b;
    public boolean c;
    public final /* synthetic */ int d;
    public final /* synthetic */ Object e;

    public C0204b(int i) {
        this.a = i;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.b < this.a;
    }

    @Override // java.util.Iterator
    public final Object next() {
        Object objG;
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        int i = this.b;
        switch (this.d) {
            case 0:
                objG = ((C0208f) this.e).g(i);
                break;
            case 1:
                objG = ((C0208f) this.e).k(i);
                break;
            default:
                objG = ((C0209g) this.e).b[i];
                break;
        }
        this.b++;
        this.c = true;
        return objG;
    }

    @Override // java.util.Iterator
    public final void remove() {
        if (!this.c) {
            Intrinsics.checkNotNullParameter("Call next() before removing an element.", "message");
            throw new IllegalStateException("Call next() before removing an element.");
        }
        int i = this.b - 1;
        this.b = i;
        switch (this.d) {
            case 0:
                ((C0208f) this.e).i(i);
                break;
            case 1:
                ((C0208f) this.e).i(i);
                break;
            default:
                ((C0209g) this.e).a(i);
                break;
        }
        this.a--;
        this.c = false;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C0204b(C0209g c0209g) {
        this(c0209g.c);
        this.d = 2;
        this.e = c0209g;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C0204b(C0208f c0208f, int i) {
        this(c0208f.c);
        this.d = i;
        switch (i) {
            case 1:
                this.e = c0208f;
                this(c0208f.c);
                break;
            default:
                this.e = c0208f;
                break;
        }
    }
}
