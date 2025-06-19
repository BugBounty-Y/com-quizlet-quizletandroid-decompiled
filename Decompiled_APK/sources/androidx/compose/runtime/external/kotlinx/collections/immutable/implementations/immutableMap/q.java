package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

/* loaded from: classes.dex */
public final class q extends o {
    public final h e;

    public q(h hVar) {
        super(0);
        this.e = hVar;
    }

    @Override // java.util.Iterator
    public final Object next() {
        int i = this.d;
        this.d = i + 2;
        Object[] objArr = this.b;
        return new b(this.e, objArr[i], objArr[i + 1]);
    }
}
