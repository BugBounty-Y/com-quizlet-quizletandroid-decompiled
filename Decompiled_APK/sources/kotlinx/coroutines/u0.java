package kotlinx.coroutines;

import java.util.concurrent.CancellationException;
import kotlin.jvm.functions.Function1;
import kotlin.sequences.Sequence;

/* loaded from: classes3.dex */
public final class u0 extends kotlin.coroutines.a implements InterfaceC5025j0 {
    public static final u0 a = new u0(C5023i0.a);

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final InterfaceC5031o C(q0 q0Var) {
        return v0.a;
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final Q Q(Function1 function1) {
        return v0.a;
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final boolean a() {
        return true;
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final Sequence d() {
        return kotlin.sequences.d.a;
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final boolean d0() {
        return false;
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final boolean isCancelled() {
        return false;
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0, kotlinx.coroutines.channels.w
    public final void j(CancellationException cancellationException) {
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final Object p(kotlin.coroutines.jvm.internal.c cVar) {
        throw new UnsupportedOperationException("This job is always active");
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final Q q(boolean z, boolean z2, Function1 function1) {
        return v0.a;
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final boolean start() {
        return false;
    }

    public final String toString() {
        return "NonCancellable";
    }

    @Override // kotlinx.coroutines.InterfaceC5025j0
    public final CancellationException y() {
        throw new IllegalStateException("This job is always active");
    }
}
