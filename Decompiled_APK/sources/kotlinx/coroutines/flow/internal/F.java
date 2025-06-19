package kotlinx.coroutines.flow.internal;

import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class F implements InterfaceC5002j {
    public final kotlinx.coroutines.channels.u a;

    public F(kotlinx.coroutines.channels.u uVar) {
        this.a = uVar;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        Object objS = ((kotlinx.coroutines.channels.t) this.a).d.s(obj, hVar);
        return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
    }
}
