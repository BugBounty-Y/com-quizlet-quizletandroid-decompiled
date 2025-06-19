package kotlin;

import kotlin.coroutines.CoroutineContext;

/* renamed from: kotlin.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4909c extends AbstractC4908b implements kotlin.coroutines.h {
    public kotlinx.serialization.json.internal.s a;
    public Unit b;
    public kotlin.coroutines.h c;
    public Object d;

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return kotlin.coroutines.n.a;
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        this.c = null;
        this.d = obj;
    }
}
