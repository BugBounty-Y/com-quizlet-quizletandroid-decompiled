package kotlinx.coroutines;

import java.util.concurrent.CancellationException;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.sequences.Sequence;

/* renamed from: kotlinx.coroutines.j0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public interface InterfaceC5025j0 extends CoroutineContext.Element {
    InterfaceC5031o C(q0 q0Var);

    Q Q(Function1 function1);

    boolean a();

    Sequence d();

    boolean d0();

    boolean isCancelled();

    void j(CancellationException cancellationException);

    Object p(kotlin.coroutines.jvm.internal.c cVar);

    Q q(boolean z, boolean z2, Function1 function1);

    boolean start();

    CancellationException y();
}
