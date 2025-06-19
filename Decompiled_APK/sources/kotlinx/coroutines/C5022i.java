package kotlinx.coroutines;

import java.util.concurrent.ScheduledFuture;
import kotlin.jvm.functions.Function1;

/* renamed from: kotlinx.coroutines.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5022i implements InterfaceC5024j {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C5022i(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlinx.coroutines.InterfaceC5024j
    public final void b(Throwable th) {
        switch (this.a) {
            case 0:
                ((ScheduledFuture) this.b).cancel(false);
                break;
            case 1:
                ((Function1) this.b).invoke(th);
                break;
            default:
                ((Q) this.b).dispose();
                break;
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return "CancelFutureOnCancel[" + ((ScheduledFuture) this.b) + ']';
            case 1:
                return "CancelHandler.UserSupplied[" + ((Function1) this.b).getClass().getSimpleName() + '@' + E.r(this) + ']';
            default:
                return "DisposeOnCancel[" + ((Q) this.b) + ']';
        }
    }
}
