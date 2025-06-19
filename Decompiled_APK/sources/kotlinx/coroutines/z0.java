package kotlinx.coroutines;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.flow.internal.ChildCancelledException;

/* loaded from: classes3.dex */
public final class z0 extends kotlinx.coroutines.internal.p {
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ z0(CoroutineContext coroutineContext, kotlin.coroutines.h hVar, int i) {
        super(hVar, coroutineContext);
        this.e = i;
    }

    @Override // kotlinx.coroutines.q0
    public final boolean E(Throwable th) {
        switch (this.e) {
            case 0:
                return false;
            default:
                if (th instanceof ChildCancelledException) {
                    return true;
                }
                return x(th);
        }
    }
}
