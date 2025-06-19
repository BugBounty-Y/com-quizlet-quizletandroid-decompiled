package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import java.util.Iterator;

/* loaded from: classes.dex */
public abstract class o implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public Object[] b;
    public int c;
    public int d;

    public o(int i) {
        this.a = i;
        switch (i) {
            case 1:
                kotlinx.collections.immutable.implementations.immutableMap.j jVar = kotlinx.collections.immutable.implementations.immutableMap.j.e;
                this.b = kotlinx.collections.immutable.implementations.immutableMap.j.e.d;
                break;
            default:
                this.b = n.e.d;
                break;
        }
    }

    public void a(int i, int i2, Object[] objArr) {
        this.b = objArr;
        this.c = i;
        this.d = i2;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (this.d < this.c) {
                }
                break;
            default:
                if (this.d < this.c) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }
}
