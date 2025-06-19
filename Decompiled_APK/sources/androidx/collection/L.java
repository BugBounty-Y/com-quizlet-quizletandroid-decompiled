package androidx.collection;

import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public int b;
    public Object c;
    public final /* synthetic */ Object d;

    public L(kotlin.sequences.r rVar) {
        this.a = 2;
        this.d = rVar;
        this.c = rVar.a.iterator();
    }

    /* JADX WARN: Type inference failed for: r0v9, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public void a() {
        Object objInvoke;
        int i = this.b;
        kotlin.sequences.g gVar = (kotlin.sequences.g) this.d;
        if (i == -2) {
            objInvoke = ((kotlin.jvm.internal.r) gVar.b).invoke();
        } else {
            Function1 function1 = (Function1) gVar.c;
            Object obj = this.c;
            Intrinsics.d(obj);
            objInvoke = function1.invoke(obj);
        }
        this.c = objInvoke;
        this.b = objInvoke == null ? 0 : 1;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        kotlin.sequences.r rVar;
        Iterator it2;
        switch (this.a) {
            case 0:
                return ((kotlin.sequences.h) this.c).hasNext();
            case 1:
                if (this.b < 0) {
                    a();
                }
                return this.b == 1;
        }
        while (true) {
            int i = this.b;
            rVar = (kotlin.sequences.r) this.d;
            int i2 = rVar.b;
            it2 = (Iterator) this.c;
            if (i < i2 && it2.hasNext()) {
                it2.next();
                this.b++;
            }
        }
        return this.b < rVar.c && it2.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        kotlin.sequences.r rVar;
        Iterator it2;
        switch (this.a) {
            case 0:
                return ((kotlin.sequences.h) this.c).next();
            case 1:
                if (this.b < 0) {
                    a();
                }
                if (this.b == 0) {
                    throw new NoSuchElementException();
                }
                Object obj = this.c;
                Intrinsics.e(obj, "null cannot be cast to non-null type T of kotlin.sequences.GeneratorSequence");
                this.b = -1;
                return obj;
        }
        while (true) {
            int i = this.b;
            rVar = (kotlin.sequences.r) this.d;
            int i2 = rVar.b;
            it2 = (Iterator) this.c;
            if (i < i2 && it2.hasNext()) {
                it2.next();
                this.b++;
            }
        }
        int i3 = this.b;
        if (i3 >= rVar.c) {
            throw new NoSuchElementException();
        }
        this.b = i3 + 1;
        return it2.next();
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                int i = this.b;
                if (i != -1) {
                    ((M) this.d).b.k(i);
                    this.b = -1;
                    return;
                }
                return;
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public L(kotlin.sequences.g gVar) {
        this.a = 1;
        this.d = gVar;
        this.b = -2;
    }

    public L(M m) {
        this.a = 0;
        this.d = m;
        this.b = -1;
        this.c = kotlin.sequences.j.a(new K(m, this, null));
    }
}
