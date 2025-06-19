package kotlinx.coroutines.flow.internal;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: kotlinx.coroutines.flow.internal.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5001i extends AbstractC5000h {
    public C5001i(InterfaceC4992i interfaceC4992i, CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar, int i2) {
        super((i2 & 4) != 0 ? -3 : i, (i2 & 2) != 0 ? kotlin.coroutines.n.a : coroutineContext, (i2 & 8) != 0 ? kotlinx.coroutines.channels.a.a : aVar, interfaceC4992i);
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final AbstractC4998f f(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return new C5001i(i, coroutineContext, aVar, this.d);
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final InterfaceC4992i i() {
        return this.d;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC5000h
    public final Object k(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        Object objB = this.d.b(interfaceC5002j, hVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }
}
