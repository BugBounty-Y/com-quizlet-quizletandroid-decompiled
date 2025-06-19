package kotlinx.collections.immutable.implementations.persistentOrderedSet;

import java.util.ConcurrentModificationException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes3.dex */
public final class d extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c {
    public final c e;
    public Object f;
    public boolean g;
    public int h;

    /* JADX WARN: Illegal instructions before constructor call */
    public d(c builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        Object obj = builder.b;
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = builder.d;
        super(obj, dVar, 2);
        this.e = builder;
        this.h = dVar.e;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c, java.util.Iterator
    public final Object next() {
        if (this.e.d.e != this.h) {
            throw new ConcurrentModificationException();
        }
        Object next = super.next();
        this.f = next;
        this.g = true;
        return next;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet.c, java.util.Iterator
    public final void remove() {
        if (!this.g) {
            throw new IllegalStateException();
        }
        Object obj = this.f;
        c cVar = this.e;
        O.a(cVar).remove(obj);
        this.f = null;
        this.g = false;
        this.h = cVar.d.e;
        this.d--;
    }
}
