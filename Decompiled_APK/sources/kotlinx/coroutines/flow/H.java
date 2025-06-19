package kotlinx.coroutines.flow;

import kotlin.Unit;
import kotlinx.coroutines.flow.internal.AbortFlowException;

/* loaded from: classes3.dex */
public final class H implements InterfaceC5002j {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlin.jvm.internal.J b;

    public /* synthetic */ H(kotlin.jvm.internal.J j, int i) {
        this.a = i;
        this.b = j;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                this.b.a = obj;
                throw new AbortFlowException(this);
            case 1:
                this.b.a = obj;
                throw new AbortFlowException(this);
            case 2:
                this.b.a = obj;
                return Unit.a;
            default:
                this.b.a = obj;
                return Unit.a;
        }
    }
}
