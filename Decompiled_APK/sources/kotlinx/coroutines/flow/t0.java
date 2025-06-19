package kotlinx.coroutines.flow;

import com.android.billingclient.api.C1472a;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.flow.internal.AbstractC4993a;
import kotlinx.coroutines.flow.internal.AbstractC4994b;
import kotlinx.coroutines.flow.internal.AbstractC4995c;

/* loaded from: classes3.dex */
public final class t0 extends AbstractC4995c {
    public final AtomicReference a = new AtomicReference(null);

    @Override // kotlinx.coroutines.flow.internal.AbstractC4995c
    public final boolean a(AbstractC4993a abstractC4993a) {
        AtomicReference atomicReference = this.a;
        if (atomicReference.get() != null) {
            return false;
        }
        atomicReference.set(e0.b);
        return true;
    }

    @Override // kotlinx.coroutines.flow.internal.AbstractC4995c
    public final kotlin.coroutines.h[] b(AbstractC4993a abstractC4993a) {
        this.a.set(null);
        return AbstractC4994b.a;
    }

    public final Object c(r0 frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        AtomicReference atomicReference = this.a;
        C1472a c1472a = e0.b;
        while (true) {
            if (atomicReference.compareAndSet(c1472a, c5028l)) {
                break;
            }
            if (atomicReference.get() != c1472a) {
                kotlin.p pVar = kotlin.r.b;
                c5028l.resumeWith(Unit.a);
                break;
            }
        }
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ == aVar ? objQ : Unit.a;
    }
}
