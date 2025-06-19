package kotlin.sequences;

import androidx.core.view.Z;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends i implements Iterator, kotlin.coroutines.h, kotlin.jvm.internal.markers.a {
    public int a;
    public Object b;
    public Iterator c;
    public kotlin.coroutines.h d;

    @Override // kotlin.sequences.i
    public final void a(Object obj, kotlin.coroutines.jvm.internal.a frame) {
        this.b = obj;
        this.a = 3;
        this.d = frame;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Intrinsics.checkNotNullParameter(frame, "frame");
    }

    @Override // kotlin.sequences.i
    public final Object d(Iterator it2, Z frame) {
        if (!it2.hasNext()) {
            return Unit.a;
        }
        this.c = it2;
        this.a = 2;
        this.d = frame;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Intrinsics.checkNotNullParameter(frame, "frame");
        return aVar;
    }

    public final RuntimeException e() {
        int i = this.a;
        if (i == 4) {
            return new NoSuchElementException();
        }
        if (i == 5) {
            return new IllegalStateException("Iterator has failed.");
        }
        return new IllegalStateException("Unexpected state of the iterator: " + this.a);
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return kotlin.coroutines.n.a;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        while (true) {
            int i = this.a;
            if (i != 0) {
                if (i != 1) {
                    if (i == 2 || i == 3) {
                        return true;
                    }
                    if (i == 4) {
                        return false;
                    }
                    throw e();
                }
                Iterator it2 = this.c;
                Intrinsics.d(it2);
                if (it2.hasNext()) {
                    this.a = 2;
                    return true;
                }
                this.c = null;
            }
            this.a = 5;
            kotlin.coroutines.h hVar = this.d;
            Intrinsics.d(hVar);
            this.d = null;
            kotlin.p pVar = kotlin.r.b;
            hVar.resumeWith(Unit.a);
        }
    }

    @Override // java.util.Iterator
    public final Object next() {
        int i = this.a;
        if (i == 0 || i == 1) {
            if (hasNext()) {
                return next();
            }
            throw new NoSuchElementException();
        }
        if (i == 2) {
            this.a = 1;
            Iterator it2 = this.c;
            Intrinsics.d(it2);
            return it2.next();
        }
        if (i != 3) {
            throw e();
        }
        this.a = 0;
        Object obj = this.b;
        this.b = null;
        return obj;
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        androidx.glance.appwidget.protobuf.Z.e(obj);
        this.a = 4;
    }
}
