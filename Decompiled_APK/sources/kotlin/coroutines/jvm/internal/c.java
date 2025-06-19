package kotlin.coroutines.jvm.internal;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.j;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C5028l;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class c extends a {
    private final CoroutineContext _context;
    private transient kotlin.coroutines.h<Object> intercepted;

    public c(kotlin.coroutines.h hVar, CoroutineContext coroutineContext) {
        super(hVar);
        this._context = coroutineContext;
    }

    @Override // kotlin.coroutines.h
    @NotNull
    public CoroutineContext getContext() {
        CoroutineContext coroutineContext = this._context;
        Intrinsics.d(coroutineContext);
        return coroutineContext;
    }

    @NotNull
    public final kotlin.coroutines.h<Object> intercepted() {
        kotlin.coroutines.h<Object> hVar = this.intercepted;
        if (hVar != null) {
            return hVar;
        }
        j jVar = (j) getContext().get(j.a1);
        kotlin.coroutines.h<Object> fVar = jVar != null ? new kotlinx.coroutines.internal.f((AbstractC5040y) jVar, this) : this;
        this.intercepted = fVar;
        return fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public void releaseIntercepted() {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater;
        kotlin.coroutines.h<Object> hVar = this.intercepted;
        if (hVar != null && hVar != this) {
            CoroutineContext.Element element = getContext().get(j.a1);
            Intrinsics.d(element);
            kotlinx.coroutines.internal.f fVar = (kotlinx.coroutines.internal.f) hVar;
            do {
                atomicReferenceFieldUpdater = kotlinx.coroutines.internal.f.h;
            } while (atomicReferenceFieldUpdater.get(fVar) == kotlinx.coroutines.internal.b.c);
            Object obj = atomicReferenceFieldUpdater.get(fVar);
            C5028l c5028l = obj instanceof C5028l ? (C5028l) obj : null;
            if (c5028l != null) {
                c5028l.n();
            }
        }
        this.intercepted = b.a;
    }

    public c(kotlin.coroutines.h hVar) {
        this(hVar, hVar != null ? hVar.getContext() : null);
    }
}
