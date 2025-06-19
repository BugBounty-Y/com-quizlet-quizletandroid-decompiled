package kotlinx.coroutines.flow.internal;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class m extends AbstractC5000h {
    public final kotlin.coroutines.jvm.internal.i e;

    /* JADX WARN: Multi-variable type inference failed */
    public m(kotlin.jvm.functions.c cVar, InterfaceC4992i interfaceC4992i, CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        super(i, coroutineContext, aVar, interfaceC4992i);
        this.e = (kotlin.coroutines.jvm.internal.i) cVar;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final AbstractC4998f f(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return new m(this.e, this.d, coroutineContext, i, aVar);
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC5000h
    public final Object k(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        Object objM = kotlinx.coroutines.E.m(new l(this, interfaceC5002j, null), hVar);
        return objM == kotlin.coroutines.intrinsics.a.a ? objM : Unit.a;
    }
}
