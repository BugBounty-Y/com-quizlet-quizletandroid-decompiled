package kotlinx.coroutines.flow;

import java.util.List;
import kotlin.coroutines.CoroutineContext;

/* loaded from: classes3.dex */
public final class Y implements a0, InterfaceC4992i, kotlinx.coroutines.flow.internal.z {
    public final /* synthetic */ W a;

    public Y(W w) {
        this.a = w;
    }

    @Override // kotlinx.coroutines.flow.a0
    public final List a() {
        return this.a.a();
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        return this.a.b(interfaceC5002j, hVar);
    }

    @Override // kotlinx.coroutines.flow.internal.z
    public final InterfaceC4992i c(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return e0.t(this, coroutineContext, i, aVar);
    }
}
