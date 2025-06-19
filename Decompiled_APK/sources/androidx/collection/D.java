package androidx.collection;

import java.util.List;
import java.util.ListIterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D implements ListIterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public final Object b;
    public int c;

    public D(int i, int i2, List list) {
        this.a = i2;
        switch (i2) {
            case 1:
                this.b = list;
                this.c = i;
                break;
            default:
                Intrinsics.checkNotNullParameter(list, "list");
                this.b = list;
                this.c = i - 1;
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.List] */
    @Override // java.util.ListIterator
    public final void add(Object obj) {
        switch (this.a) {
            case 0:
                int i = this.c + 1;
                this.c = i;
                this.b.add(i, obj);
                break;
            default:
                this.b.add(this.c, obj);
                this.c++;
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v3, types: [java.lang.Object, java.util.List] */
    @Override // java.util.ListIterator, java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                return this.c < this.b.size() - 1;
            default:
                return this.c < this.b.size();
        }
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        switch (this.a) {
            case 0:
                if (this.c >= 0) {
                }
                break;
            default:
                if (this.c > 0) {
                }
                break;
        }
        return false;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.lang.Object, java.util.List] */
    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                int i = this.c + 1;
                this.c = i;
                return this.b.get(i);
            default:
                int i2 = this.c;
                this.c = i2 + 1;
                return this.b.get(i2);
        }
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        switch (this.a) {
            case 0:
                return this.c + 1;
            default:
                return this.c;
        }
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.lang.Object, java.util.List] */
    @Override // java.util.ListIterator
    public final Object previous() {
        switch (this.a) {
            case 0:
                int i = this.c;
                this.c = i - 1;
                return this.b.get(i);
            default:
                int i2 = this.c - 1;
                this.c = i2;
                return this.b.get(i2);
        }
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        switch (this.a) {
            case 0:
                return this.c;
            default:
                return this.c - 1;
        }
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.List] */
    @Override // java.util.ListIterator, java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                this.b.remove(this.c);
                this.c--;
                break;
            default:
                int i = this.c - 1;
                this.c = i;
                this.b.remove(i);
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.List] */
    @Override // java.util.ListIterator
    public final void set(Object obj) {
        switch (this.a) {
            case 0:
                this.b.set(this.c, obj);
                break;
            default:
                this.b.set(this.c, obj);
                break;
        }
    }
}
