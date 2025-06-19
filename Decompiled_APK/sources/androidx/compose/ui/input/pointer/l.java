package androidx.compose.ui.input.pointer;

import android.view.MotionEvent;
import com.google.android.gms.internal.measurement.C3083y1;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class l {
    public static final C0878a a = new C0878a(1000);
    public static final C0878a b;
    public static final StackTraceElement[] c;

    static {
        new C0878a(1007);
        new C0878a(1008);
        b = new C0878a(1002);
        c = new StackTraceElement[0];
    }

    public static final boolean a(n nVar) {
        return !nVar.h && nVar.d;
    }

    public static final boolean b(n nVar) {
        return (nVar.b() || !nVar.h || nVar.d) ? false : true;
    }

    public static final boolean c(n nVar) {
        return nVar.h && !nVar.d;
    }

    public static final boolean d(n nVar, long j) {
        long j2 = nVar.c;
        float fD = androidx.compose.ui.geometry.b.d(j2);
        float fE = androidx.compose.ui.geometry.b.e(j2);
        return fD < DefinitionKt.NO_Float_VALUE || fD > ((float) ((int) (j >> 32))) || fE < DefinitionKt.NO_Float_VALUE || fE > ((float) ((int) (j & 4294967295L)));
    }

    public static final boolean e(n nVar, long j, long j2) {
        if (nVar.i != 1) {
            return d(nVar, j);
        }
        long j3 = nVar.c;
        float fD = androidx.compose.ui.geometry.b.d(j3);
        float fE = androidx.compose.ui.geometry.b.e(j3);
        return fD < (-androidx.compose.ui.geometry.e.d(j2)) || fD > androidx.compose.ui.geometry.e.d(j2) + ((float) ((int) (j >> 32))) || fE < (-androidx.compose.ui.geometry.e.b(j2)) || fE > androidx.compose.ui.geometry.e.b(j2) + ((float) ((int) (j & 4294967295L)));
    }

    public static androidx.compose.ui.q f(androidx.compose.ui.q qVar, C0878a c0878a) {
        return qVar.g(new PointerHoverIconModifierElement(c0878a));
    }

    public static final long g(n nVar, boolean z) {
        long jG = androidx.compose.ui.geometry.b.g(nVar.c, nVar.g);
        if (z || !nVar.b()) {
            return jG;
        }
        return 0L;
    }

    public static final void h(f fVar, long j, Function1 function1, boolean z) {
        C3083y1 c3083y1 = fVar.b;
        MotionEvent motionEvent = c3083y1 != null ? (MotionEvent) ((com.quizlet.data.repository.qclass.c) c3083y1.d).c : null;
        if (motionEvent == null) {
            throw new IllegalArgumentException("The PointerEvent receiver cannot have a null MotionEvent.");
        }
        int action = motionEvent.getAction();
        if (z) {
            motionEvent.setAction(3);
        }
        motionEvent.offsetLocation(-androidx.compose.ui.geometry.b.d(j), -androidx.compose.ui.geometry.b.e(j));
        function1.invoke(motionEvent);
        motionEvent.offsetLocation(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
        motionEvent.setAction(action);
    }
}
