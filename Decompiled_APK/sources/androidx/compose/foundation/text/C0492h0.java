package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.text.AbstractC0996h;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.input.C1007j;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0492h0 {
    public t0 a;
    public final C0813o0 b;
    public final androidx.compose.ui.platform.Q0 c;
    public final com.quizlet.data.repository.explanations.myexplanations.a d;
    public androidx.compose.ui.text.input.H e;
    public final InterfaceC0773a0 f;
    public final InterfaceC0773a0 g;
    public androidx.compose.ui.layout.r h;
    public final InterfaceC0773a0 i;
    public C0995g j;
    public final InterfaceC0773a0 k;
    public final InterfaceC0773a0 l;
    public final InterfaceC0773a0 m;
    public final InterfaceC0773a0 n;
    public final InterfaceC0773a0 o;
    public boolean p;
    public final InterfaceC0773a0 q;
    public final C0486e0 r;
    public Function1 s;
    public final D t;
    public final D u;
    public final com.google.android.gms.cloudmessaging.k v;
    public long w;
    public final InterfaceC0773a0 x;
    public final InterfaceC0773a0 y;

    public C0492h0(t0 t0Var, C0813o0 c0813o0, androidx.compose.ui.platform.Q0 q0) {
        this.a = t0Var;
        this.b = c0813o0;
        this.c = q0;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = new com.quizlet.data.repository.explanations.myexplanations.a(4, false);
        C0995g c0995g = AbstractC0996h.a;
        long j = androidx.compose.ui.text.K.b;
        androidx.compose.ui.text.input.A a = new androidx.compose.ui.text.input.A(c0995g, j, (androidx.compose.ui.text.K) null);
        aVar.b = a;
        aVar.c = new C1007j(c0995g, a.b);
        this.d = aVar;
        Boolean bool = Boolean.FALSE;
        this.f = C0776c.z(bool);
        this.g = C0776c.z(new androidx.compose.ui.unit.e(0));
        this.i = C0776c.z(null);
        this.k = C0776c.z(V.a);
        this.l = C0776c.z(bool);
        this.m = C0776c.z(bool);
        this.n = C0776c.z(bool);
        this.o = C0776c.z(bool);
        this.p = true;
        this.q = C0776c.z(Boolean.TRUE);
        this.r = new C0486e0(q0);
        this.s = C0491h.h;
        this.t = new D(this, 5);
        this.u = new D(this, 4);
        this.v = androidx.compose.ui.graphics.F.g();
        this.w = C0861v.g;
        this.x = C0776c.z(new androidx.compose.ui.text.K(j));
        this.y = C0776c.z(new androidx.compose.ui.text.K(j));
    }

    public final V a() {
        return (V) ((androidx.compose.runtime.L0) this.k).getValue();
    }

    public final boolean b() {
        return ((Boolean) ((androidx.compose.runtime.L0) this.f).getValue()).booleanValue();
    }

    public final androidx.compose.ui.layout.r c() {
        androidx.compose.ui.layout.r rVar = this.h;
        if (rVar == null || !rVar.k()) {
            return null;
        }
        return rVar;
    }

    public final K0 d() {
        return (K0) ((androidx.compose.runtime.L0) this.i).getValue();
    }

    public final void e(long j) {
        ((androidx.compose.runtime.L0) this.y).setValue(new androidx.compose.ui.text.K(j));
    }

    public final void f(long j) {
        ((androidx.compose.runtime.L0) this.x).setValue(new androidx.compose.ui.text.K(j));
    }
}
