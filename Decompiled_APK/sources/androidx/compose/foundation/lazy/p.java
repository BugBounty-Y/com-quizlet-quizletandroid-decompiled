package androidx.compose.foundation.lazy;

import android.os.Build;
import android.os.Trace;
import androidx.appcompat.app.L;
import androidx.compose.animation.d0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.layout.V;
import androidx.compose.ui.node.G;
import androidx.work.C1422c;
import androidx.work.impl.F;
import androidx.work.impl.WorkerStoppedException;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(int i, Object obj, Object obj2, Object obj3, boolean z) {
        super(1);
        this.a = i;
        this.c = obj;
        this.b = z;
        this.d = obj2;
        this.e = obj3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        String methodName;
        switch (this.a) {
            case 0:
                V v = (V) obj;
                ArrayList arrayList = (ArrayList) this.c;
                int size = arrayList.size();
                int i = 0;
                while (true) {
                    r rVar = (r) this.d;
                    boolean z = this.b;
                    if (i >= size) {
                        if (rVar != null) {
                            rVar.l(v, z);
                        }
                        ((InterfaceC0773a0) this.e).getValue();
                        return Unit.a;
                    }
                    r rVar2 = (r) arrayList.get(i);
                    if (rVar2 != rVar) {
                        rVar2.l(v, z);
                    }
                    i++;
                }
            case 1:
                G g = (G) obj;
                g.b();
                if (((Boolean) ((Function0) this.c).invoke()).booleanValue()) {
                    boolean z2 = this.b;
                    C0853m c0853m = (C0853m) this.e;
                    C0848h c0848h = (C0848h) this.d;
                    androidx.compose.ui.graphics.drawscope.b bVar = g.a;
                    if (z2) {
                        long jO0 = bVar.o0();
                        com.quizlet.data.repository.folderset.c cVar = bVar.b;
                        long jR = cVar.r();
                        cVar.o().e();
                        try {
                            ((L) cVar.b).Q(-1.0f, 1.0f, jO0);
                            bVar.d(c0848h, c0853m);
                        } finally {
                            d0.y(cVar, jR);
                        }
                    } else {
                        bVar.d(c0848h, c0853m);
                    }
                }
                return Unit.a;
            default:
                Throwable th = (Throwable) obj;
                if (th instanceof WorkerStoppedException) {
                    ((androidx.work.y) this.c).stop(((WorkerStoppedException) th).a);
                }
                if (this.b && (methodName = (String) this.d) != null) {
                    F f = (F) this.e;
                    C1422c c1422c = f.f;
                    int iHashCode = f.a.hashCode();
                    c1422c.m.getClass();
                    Intrinsics.checkNotNullParameter(methodName, "methodName");
                    if (Build.VERSION.SDK_INT >= 29) {
                        androidx.tracing.a.b(AbstractC3359k2.f(methodName), iHashCode);
                    } else {
                        String strF = AbstractC3359k2.f(methodName);
                        try {
                            if (AbstractC3359k2.d == null) {
                                AbstractC3359k2.d = Trace.class.getMethod("asyncTraceEnd", Long.TYPE, String.class, Integer.TYPE);
                            }
                            AbstractC3359k2.d.invoke(null, Long.valueOf(AbstractC3359k2.a), strF, Integer.valueOf(iHashCode));
                        } catch (Exception e) {
                            AbstractC3359k2.c(e);
                        }
                    }
                }
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(ArrayList arrayList, r rVar, boolean z, InterfaceC0773a0 interfaceC0773a0) {
        super(1);
        this.a = 0;
        this.c = arrayList;
        this.d = rVar;
        this.b = z;
        this.e = interfaceC0773a0;
    }
}
