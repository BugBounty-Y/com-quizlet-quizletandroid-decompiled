package kotlinx.coroutines.flow;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.flow.internal.AbstractC4998f;

/* renamed from: kotlinx.coroutines.flow.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4987d extends AbstractC4998f {
    public static final /* synthetic */ AtomicIntegerFieldUpdater f = AtomicIntegerFieldUpdater.newUpdater(C4987d.class, "consumed$volatile");
    private volatile /* synthetic */ int consumed$volatile;
    public final kotlinx.coroutines.channels.h d;
    public final boolean e;

    public /* synthetic */ C4987d(kotlinx.coroutines.channels.h hVar, boolean z) {
        this(hVar, z, kotlin.coroutines.n.a, -3, kotlinx.coroutines.channels.a.a);
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f, kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) throws Throwable {
        if (this.b != -3) {
            Object objB = super.b(interfaceC5002j, hVar);
            return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
        }
        boolean z = this.e;
        if (z && f.getAndSet(this, 1) == 1) {
            throw new IllegalStateException("ReceiveChannel.consumeAsFlow can be collected just once");
        }
        Object objO = e0.o(interfaceC5002j, this.d, z, hVar);
        return objO == kotlin.coroutines.intrinsics.a.a ? objO : Unit.a;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final String d() {
        return "channel=" + this.d;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final Object e(kotlinx.coroutines.channels.u uVar, kotlin.coroutines.h hVar) throws Throwable {
        Object objO = e0.o(new kotlinx.coroutines.flow.internal.F(uVar), this.d, this.e, hVar);
        return objO == kotlin.coroutines.intrinsics.a.a ? objO : Unit.a;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final AbstractC4998f f(CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return new C4987d(this.d, this.e, coroutineContext, i, aVar);
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final InterfaceC4992i i() {
        return new C4987d(this.d, this.e);
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4998f
    public final kotlinx.coroutines.channels.w j(kotlinx.coroutines.C c) {
        if (this.e && f.getAndSet(this, 1) == 1) {
            throw new IllegalStateException("ReceiveChannel.consumeAsFlow can be collected just once");
        }
        return this.b == -3 ? this.d : super.j(c);
    }

    public C4987d(kotlinx.coroutines.channels.h hVar, boolean z, CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        super(coroutineContext, i, aVar);
        this.d = hVar;
        this.e = z;
    }
}
