package kotlin.coroutines;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.jvm.internal.Intrinsics;
import kotlin.q;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class p implements h, kotlin.coroutines.jvm.internal.d {

    @NotNull
    private static final o b = new o(null);
    public static final AtomicReferenceFieldUpdater c = AtomicReferenceFieldUpdater.newUpdater(p.class, Object.class, "result");
    public final h a;
    private volatile Object result;

    public p(h delegate, kotlin.coroutines.intrinsics.a aVar) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.a = delegate;
        this.result = aVar;
    }

    public final Object a() throws Throwable {
        Object obj = this.result;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.b;
        if (obj == aVar) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = c;
            kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
            while (!atomicReferenceFieldUpdater.compareAndSet(this, aVar, aVar2)) {
                if (atomicReferenceFieldUpdater.get(this) != aVar) {
                    obj = this.result;
                }
            }
            return kotlin.coroutines.intrinsics.a.a;
        }
        if (obj == kotlin.coroutines.intrinsics.a.c) {
            return kotlin.coroutines.intrinsics.a.a;
        }
        if (obj instanceof q) {
            throw ((q) obj).a;
        }
        return obj;
    }

    @Override // kotlin.coroutines.jvm.internal.d
    public final kotlin.coroutines.jvm.internal.d getCallerFrame() {
        h hVar = this.a;
        if (hVar instanceof kotlin.coroutines.jvm.internal.d) {
            return (kotlin.coroutines.jvm.internal.d) hVar;
        }
        return null;
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return this.a.getContext();
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        while (true) {
            Object obj2 = this.result;
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.b;
            if (obj2 == aVar) {
                AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = c;
                while (!atomicReferenceFieldUpdater.compareAndSet(this, aVar, obj)) {
                    if (atomicReferenceFieldUpdater.get(this) != aVar) {
                        break;
                    }
                }
                return;
            }
            kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
            if (obj2 != aVar2) {
                throw new IllegalStateException("Already resumed");
            }
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2 = c;
            kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.c;
            while (!atomicReferenceFieldUpdater2.compareAndSet(this, aVar2, aVar3)) {
                if (atomicReferenceFieldUpdater2.get(this) != aVar2) {
                    break;
                }
            }
            this.a.resumeWith(obj);
            return;
        }
    }

    public final String toString() {
        return "SafeContinuation for " + this.a;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public p(h delegate) {
        this(delegate, kotlin.coroutines.intrinsics.a.b);
        Intrinsics.checkNotNullParameter(delegate, "delegate");
    }
}
