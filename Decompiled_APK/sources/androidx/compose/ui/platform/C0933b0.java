package androidx.compose.ui.platform;

import android.view.Choreographer;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* renamed from: androidx.compose.ui.platform.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0933b0 implements androidx.compose.runtime.W {
    public final Choreographer a;
    public final Z b;

    public C0933b0(Choreographer choreographer, Z z) {
        this.a = choreographer;
        this.b = z;
    }

    @Override // androidx.compose.runtime.W
    public final Object P(Function1 function1, kotlin.coroutines.h frame) {
        Z z = this.b;
        if (z == null) {
            CoroutineContext.Element element = frame.getContext().get(kotlin.coroutines.j.a1);
            z = element instanceof Z ? (Z) element : null;
        }
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        ChoreographerFrameCallbackC0931a0 choreographerFrameCallbackC0931a0 = new ChoreographerFrameCallbackC0931a0(c5028l, this, function1);
        if (z == null || !Intrinsics.b(z.b, this.a)) {
            this.a.postFrameCallback(choreographerFrameCallbackC0931a0);
            c5028l.u(new androidx.compose.foundation.text.selection.n0(24, this, choreographerFrameCallbackC0931a0));
        } else {
            synchronized (z.d) {
                try {
                    z.f.add(choreographerFrameCallbackC0931a0);
                    if (!z.i) {
                        z.i = true;
                        z.b.postFrameCallback(z.j);
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            c5028l.u(new androidx.compose.foundation.text.selection.n0(23, z, choreographerFrameCallbackC0931a0));
        }
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final Object fold(Object obj, Function2 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        return operation.invoke(obj, this);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.a(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.b(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext plus(CoroutineContext coroutineContext) {
        return kotlin.coroutines.k.c(coroutineContext, this);
    }
}
