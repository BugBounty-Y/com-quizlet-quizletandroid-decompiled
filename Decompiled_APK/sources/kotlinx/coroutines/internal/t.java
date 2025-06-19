package kotlinx.coroutines.internal;

import com.android.billingclient.api.C1472a;
import com.quizlet.ui.compose.C4830x;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.B0;

/* loaded from: classes3.dex */
public abstract class t {
    public static final C1472a a = new C1472a("NO_THREAD_ELEMENTS", 2);
    public static final C4830x b = new C4830x(19, 0);
    public static final C4830x c = new C4830x(20, 0);
    public static final C4830x d = new C4830x(21, 0);

    public static final void a(CoroutineContext coroutineContext, Object obj) {
        if (obj == a) {
            return;
        }
        if (!(obj instanceof v)) {
            Object objFold = coroutineContext.fold(null, c);
            Intrinsics.e(objFold, "null cannot be cast to non-null type kotlinx.coroutines.ThreadContextElement<kotlin.Any?>");
            android.support.v4.media.session.a.A(objFold);
            throw null;
        }
        v vVar = (v) obj;
        B0[] b0Arr = vVar.c;
        int length = b0Arr.length - 1;
        if (length < 0) {
            return;
        }
        B0 b0 = b0Arr[length];
        Intrinsics.d(null);
        Object obj2 = vVar.b[length];
        throw null;
    }

    public static final Object b(CoroutineContext coroutineContext) {
        Object objFold = coroutineContext.fold(0, b);
        Intrinsics.d(objFold);
        return objFold;
    }

    public static final Object c(CoroutineContext coroutineContext, Object obj) {
        if (obj == null) {
            obj = b(coroutineContext);
        }
        if (obj == 0) {
            return a;
        }
        if (obj instanceof Integer) {
            return coroutineContext.fold(new v(((Number) obj).intValue(), coroutineContext), d);
        }
        android.support.v4.media.session.a.A(obj);
        throw null;
    }
}
