package kotlinx.coroutines.internal;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.B0;

/* loaded from: classes3.dex */
public final class v {
    public final CoroutineContext a;
    public final Object[] b;
    public final B0[] c;

    public v(int i, CoroutineContext coroutineContext) {
        this.a = coroutineContext;
        this.b = new Object[i];
        this.c = new B0[i];
    }
}
