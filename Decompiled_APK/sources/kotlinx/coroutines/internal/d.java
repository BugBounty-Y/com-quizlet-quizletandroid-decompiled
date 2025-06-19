package kotlinx.coroutines.internal;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d implements C {
    public final CoroutineContext a;

    public d(CoroutineContext coroutineContext) {
        this.a = coroutineContext;
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.a;
    }

    public final String toString() {
        return "CoroutineScope(coroutineContext=" + this.a + ')';
    }
}
