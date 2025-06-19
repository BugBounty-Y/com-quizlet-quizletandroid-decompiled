package kotlin.coroutines.jvm.internal;

import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.n;

/* loaded from: classes3.dex */
public abstract class g extends a {
    public g(kotlin.coroutines.h hVar) {
        super(hVar);
        if (hVar != null && hVar.getContext() != n.a) {
            throw new IllegalArgumentException("Coroutines with restricted suspension must have EmptyCoroutineContext");
        }
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return n.a;
    }
}
