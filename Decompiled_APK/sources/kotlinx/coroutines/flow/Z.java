package kotlinx.coroutines.flow;

import java.util.List;
import kotlin.coroutines.CoroutineContext;

/* loaded from: classes3.dex */
public final class Z implements q0, InterfaceC4992i, kotlinx.coroutines.flow.internal.z {
    public final /* synthetic */ X a;

    public Z(X x) {
        this.a = x;
    }

    @Override // kotlinx.coroutines.flow.a0
    public final List a() {
        return ((s0) this.a).a();
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) throws Throwable {
        ((s0) this.a).b(interfaceC5002j, hVar);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlinx.coroutines.flow.internal.z
    public final InterfaceC4992i c(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return (((i < 0 || i >= 2) && i != -2) || aVar != kotlinx.coroutines.channels.a.b) ? e0.t(this, coroutineContext, i, aVar) : this;
    }

    @Override // kotlinx.coroutines.flow.q0
    public final Object getValue() {
        return ((s0) this.a).getValue();
    }
}
