package coil3.compose.internal;

import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.l;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C5039x;

/* loaded from: classes.dex */
public abstract class e implements CoroutineContext {
    public final CoroutineContext a;

    public e(CoroutineContext coroutineContext) {
        this.a = coroutineContext;
    }

    public final boolean equals(Object obj) {
        return Intrinsics.b(this.a, obj);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final Object fold(Object obj, Function2 function2) {
        return this.a.fold(obj, function2);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(l lVar) {
        return this.a.get(lVar);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(l lVar) {
        CoroutineContext coroutineContextMinusKey = this.a.minusKey(lVar);
        int i = g.b;
        C5039x c5039x = AbstractC5040y.a;
        AbstractC5040y abstractC5040y = (AbstractC5040y) get(c5039x);
        AbstractC5040y abstractC5040y2 = (AbstractC5040y) coroutineContextMinusKey.get(c5039x);
        if ((abstractC5040y instanceof d) && !Intrinsics.b(abstractC5040y, abstractC5040y2)) {
            ((d) abstractC5040y).c = 0;
        }
        return new c(coroutineContextMinusKey);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext plus(CoroutineContext coroutineContext) {
        CoroutineContext coroutineContextPlus = this.a.plus(coroutineContext);
        int i = g.b;
        C5039x c5039x = AbstractC5040y.a;
        AbstractC5040y abstractC5040y = (AbstractC5040y) get(c5039x);
        AbstractC5040y abstractC5040y2 = (AbstractC5040y) coroutineContextPlus.get(c5039x);
        if ((abstractC5040y instanceof d) && !Intrinsics.b(abstractC5040y, abstractC5040y2)) {
            ((d) abstractC5040y).c = 0;
        }
        return new c(coroutineContextPlus);
    }

    public final String toString() {
        return "ForwardingCoroutineContext(delegate=" + this.a + ')';
    }
}
