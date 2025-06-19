package kotlinx.coroutines;

import kotlin.coroutines.CoroutineContext;

/* loaded from: classes3.dex */
public final class G0 extends AbstractC5040y {
    public static final G0 b = new G0();

    @Override // kotlinx.coroutines.AbstractC5040y
    public final AbstractC5040y c0(int i) {
        throw new UnsupportedOperationException("limitedParallelism is not supported for Dispatchers.Unconfined");
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        K0 k0 = (K0) coroutineContext.get(K0.b);
        if (k0 == null) {
            throw new UnsupportedOperationException("Dispatchers.Unconfined.dispatch function can only be used by the yield function. If you wrap Unconfined dispatcher in your code, make sure you properly delegate isDispatchNeeded and dispatch calls.");
        }
        k0.a = true;
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final String toString() {
        return "Dispatchers.Unconfined";
    }
}
