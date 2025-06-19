package kotlinx.coroutines.flow.internal;

import com.android.billingclient.api.C1472a;
import com.google.android.gms.internal.mlkit_vision_camera.H1;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.z0;

/* renamed from: kotlinx.coroutines.flow.internal.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4994b {
    public static final kotlin.coroutines.h[] a = new kotlin.coroutines.h[0];
    public static final C1472a b = new C1472a("NULL", 2);
    public static final C1472a c = new C1472a("UNINITIALIZED", 2);
    public static final C1472a d = new C1472a("DONE", 2);

    public static final Object a(kotlin.coroutines.h frame, Function0 function0, kotlin.jvm.functions.c cVar, InterfaceC5002j interfaceC5002j, InterfaceC4992i[] interfaceC4992iArr) {
        p pVar = new p(null, function0, cVar, interfaceC5002j, interfaceC4992iArr);
        z0 z0Var = new z0(frame.getContext(), frame, 1);
        Object objC = H1.c(z0Var, true, z0Var, pVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objC == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objC == aVar ? objC : Unit.a;
    }

    public static /* synthetic */ InterfaceC4992i b(z zVar, CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar, int i2) {
        if ((i2 & 1) != 0) {
            coroutineContext = kotlin.coroutines.n.a;
        }
        if ((i2 & 2) != 0) {
            i = -3;
        }
        if ((i2 & 4) != 0) {
            aVar = kotlinx.coroutines.channels.a.a;
        }
        return zVar.c(coroutineContext, i, aVar);
    }

    public static final Object c(CoroutineContext coroutineContext, Object obj, Object obj2, Function2 function2, kotlin.coroutines.h frame) {
        Object objInvoke;
        Object objC = kotlinx.coroutines.internal.t.c(coroutineContext, obj2);
        try {
            G g = new G(frame, coroutineContext);
            if (function2 == null) {
                objInvoke = kotlin.coroutines.intrinsics.h.c(function2, obj, g);
            } else {
                O.d(2, function2);
                objInvoke = function2.invoke(obj, g);
            }
            kotlinx.coroutines.internal.t.a(coroutineContext, objC);
            if (objInvoke == kotlin.coroutines.intrinsics.a.a) {
                Intrinsics.checkNotNullParameter(frame, "frame");
            }
            return objInvoke;
        } catch (Throwable th) {
            kotlinx.coroutines.internal.t.a(coroutineContext, objC);
            throw th;
        }
    }
}
