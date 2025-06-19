package androidx.glance.session;

import androidx.compose.runtime.C0794f;
import androidx.compose.runtime.W;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* renamed from: androidx.glance.session.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1231i implements W {
    public final K a;
    public final C0794f b = new C0794f(new androidx.compose.ui.input.nestedscroll.b(this, 23));
    public final Object c = new Object();
    public int d = 5;
    public long e;
    public C5028l f;

    public C1231i(K k) {
        this.a = k;
    }

    @Override // androidx.compose.runtime.W
    public final Object P(Function1 function1, kotlin.coroutines.h hVar) {
        return this.b.P(function1, hVar);
    }

    public final void b() {
        synchronized (this.c) {
            C5028l c5028l = this.f;
            if (c5028l != null) {
                c5028l.b(null);
            }
        }
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final Object fold(Object obj, Function2 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        return operation.invoke(obj, this);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.a(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.b(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext plus(CoroutineContext coroutineContext) {
        return kotlin.coroutines.k.c(coroutineContext, this);
    }
}
