package io.ktor.client.engine;

import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.flow.internal.AbortFlowException;

/* loaded from: classes3.dex */
public final class k implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C5027k0 b;

    public /* synthetic */ k(C5027k0 c5027k0, int i) {
        this.a = i;
        this.b = c5027k0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Throwable th = (Throwable) obj;
                if (th != null) {
                    this.b.z(new CancellationException(th.getMessage()));
                }
                break;
            default:
                C5027k0 c5027k0 = this.b;
                if (c5027k0.a()) {
                    c5027k0.z(new AbortFlowException(c5027k0));
                }
                break;
        }
        return Unit.a;
    }
}
