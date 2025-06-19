package androidx.compose.foundation.text;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class A0 extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ C0492h0 a;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 b;
    public final /* synthetic */ androidx.compose.ui.text.input.A c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ androidx.compose.ui.text.input.s f;
    public final /* synthetic */ Q0 g;
    public final /* synthetic */ D h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A0(C0492h0 c0492h0, androidx.compose.foundation.text.selection.i0 i0Var, androidx.compose.ui.text.input.A a, boolean z, boolean z2, androidx.compose.ui.text.input.s sVar, Q0 q0, D d, int i) {
        super(3);
        this.a = c0492h0;
        this.b = i0Var;
        this.c = a;
        this.d = z;
        this.e = z2;
        this.f = sVar;
        this.g = q0;
        this.h = d;
        this.i = i;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        ((Number) obj3).intValue();
        C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
        c0814p.X(851809892);
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (objI == v) {
            objI = new androidx.compose.foundation.text.selection.o0();
            c0814p.i0(objI);
        }
        androidx.compose.foundation.text.selection.o0 o0Var = (androidx.compose.foundation.text.selection.o0) objI;
        Object objI2 = c0814p.I();
        if (objI2 == v) {
            objI2 = new T();
            c0814p.i0(objI2);
        }
        C0492h0 c0492h0 = this.a;
        androidx.compose.foundation.text.selection.i0 i0Var = this.b;
        Q0 q0 = this.g;
        y0 y0Var = new y0(c0492h0, i0Var, this.c, this.d, this.e, o0Var, this.f, q0, (T) objI2, this.h, this.i);
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        boolean zH = c0814p.h(y0Var);
        Object objI3 = c0814p.I();
        if (zH || objI3 == v) {
            z0 z0Var = new z0(1, y0Var, y0.class, "process", "process-ZmokQxo(Landroid/view/KeyEvent;)Z", 0, 0);
            c0814p.i0(z0Var);
            objI3 = z0Var;
        }
        androidx.compose.ui.q qVarD = androidx.compose.ui.input.key.c.d(nVar, (Function1) ((kotlin.reflect.f) objI3));
        c0814p.p(false);
        return qVarD;
    }
}
