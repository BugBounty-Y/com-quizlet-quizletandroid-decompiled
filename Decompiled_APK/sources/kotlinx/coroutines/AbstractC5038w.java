package kotlinx.coroutines;

import com.quizlet.ui.compose.C4830x;
import kotlin.coroutines.CoroutineContext;

/* renamed from: kotlinx.coroutines.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5038w {
    public static final CoroutineContext a(CoroutineContext coroutineContext, CoroutineContext coroutineContext2, boolean z) {
        Boolean bool = Boolean.FALSE;
        boolean zBooleanValue = ((Boolean) coroutineContext.fold(bool, new C4830x(15, (byte) 0))).booleanValue();
        boolean zBooleanValue2 = ((Boolean) coroutineContext2.fold(bool, new C4830x(15, (byte) 0))).booleanValue();
        if (!zBooleanValue && !zBooleanValue2) {
            return coroutineContext.plus(coroutineContext2);
        }
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        j.a = coroutineContext2;
        kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
        CoroutineContext coroutineContext3 = (CoroutineContext) coroutineContext.fold(nVar, new C4830x(16, (byte) 0));
        if (zBooleanValue2) {
            j.a = ((CoroutineContext) j.a).fold(nVar, new C4830x(17, (byte) 0));
        }
        return coroutineContext3.plus((CoroutineContext) j.a);
    }

    public static final CoroutineContext b(C c, CoroutineContext coroutineContext) {
        CoroutineContext coroutineContextA = a(c.getCoroutineContext(), coroutineContext, true);
        kotlinx.coroutines.scheduling.e eVar = O.a;
        return (coroutineContextA == eVar || coroutineContextA.get(kotlin.coroutines.j.a1) != null) ? coroutineContextA : coroutineContextA.plus(eVar);
    }

    public static final H0 c(kotlin.coroutines.h hVar, CoroutineContext coroutineContext, Object obj) {
        H0 h0 = null;
        if ((hVar instanceof kotlin.coroutines.jvm.internal.d) && coroutineContext.get(I0.a) != null) {
            kotlin.coroutines.jvm.internal.d callerFrame = (kotlin.coroutines.jvm.internal.d) hVar;
            while (true) {
                if ((callerFrame instanceof L) || (callerFrame = callerFrame.getCallerFrame()) == null) {
                    break;
                }
                if (callerFrame instanceof H0) {
                    h0 = (H0) callerFrame;
                    break;
                }
            }
            if (h0 != null) {
                h0.q0(coroutineContext, obj);
            }
        }
        return h0;
    }
}
