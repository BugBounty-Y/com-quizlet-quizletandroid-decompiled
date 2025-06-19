package androidx.compose.ui.node;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.layout.C0893n;
import androidx.compose.ui.platform.C0971v;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.node.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0928y extends a0 {
    public static final com.google.android.gms.cloudmessaging.k M;
    public InterfaceC0926w K;
    public C0927x L;

    static {
        com.google.android.gms.cloudmessaging.k kVarG = androidx.compose.ui.graphics.F.g();
        int i = C0861v.h;
        kVarG.f(C0861v.e);
        kVarG.l(1.0f);
        kVarG.m(1);
        M = kVarG;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public C0928y(E e, InterfaceC0926w interfaceC0926w) {
        super(e);
        this.K = interfaceC0926w;
        this.L = e.c != null ? new C0927x(this) : null;
        if ((((androidx.compose.ui.p) interfaceC0926w).a.c & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0) {
            throw new ClassCastException();
        }
    }

    @Override // androidx.compose.ui.layout.J
    public final androidx.compose.ui.layout.W B(long j) {
        x0(j);
        InterfaceC0926w interfaceC0926w = this.K;
        a0 a0Var = this.m;
        Intrinsics.d(a0Var);
        l1(interfaceC0926w.h(this, a0Var, j));
        g1();
        return this;
    }

    @Override // androidx.compose.ui.node.a0
    public final void R0() {
        if (this.L == null) {
            this.L = new C0927x(this);
        }
    }

    @Override // androidx.compose.ui.node.a0
    public final P U0() {
        return this.L;
    }

    @Override // androidx.compose.ui.node.a0
    public final androidx.compose.ui.p W0() {
        return ((androidx.compose.ui.p) this.K).a;
    }

    @Override // androidx.compose.ui.layout.J
    public final int X(int i) {
        InterfaceC0926w interfaceC0926w = this.K;
        a0 a0Var = this.m;
        Intrinsics.d(a0Var);
        return interfaceC0926w.f(this, a0Var, i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int b(int i) {
        InterfaceC0926w interfaceC0926w = this.K;
        a0 a0Var = this.m;
        Intrinsics.d(a0Var);
        return interfaceC0926w.i(this, a0Var, i);
    }

    @Override // androidx.compose.ui.node.a0
    public final void i1(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar) {
        a0 a0Var = this.m;
        Intrinsics.d(a0Var);
        a0Var.O0(interfaceC0858s, bVar);
        if (((C0971v) H.a(this.l)).getShowLayoutBounds()) {
            P0(interfaceC0858s, M);
        }
    }

    @Override // androidx.compose.ui.node.a0, androidx.compose.ui.layout.W
    public final void r0(long j, float f, androidx.compose.ui.graphics.layer.b bVar) {
        j1(j, f, null, bVar);
        t1();
    }

    @Override // androidx.compose.ui.layout.W
    public final void s0(long j, float f, Function1 function1) {
        j1(j, f, function1, null);
        t1();
    }

    public final void t1() {
        if (this.g) {
            return;
        }
        h1();
        F0().d();
        Intrinsics.d(this.m);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void u1(InterfaceC0926w interfaceC0926w) {
        if (!interfaceC0926w.equals(this.K) && (((androidx.compose.ui.p) interfaceC0926w).a.c & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0) {
            throw new ClassCastException();
        }
        this.K = interfaceC0926w;
    }

    @Override // androidx.compose.ui.layout.J
    public final int x(int i) {
        InterfaceC0926w interfaceC0926w = this.K;
        a0 a0Var = this.m;
        Intrinsics.d(a0Var);
        return interfaceC0926w.c(this, a0Var, i);
    }

    @Override // androidx.compose.ui.node.O
    public final int y0(C0893n c0893n) {
        C0927x c0927x = this.L;
        if (c0927x == null) {
            return AbstractC0910f.c(this, c0893n);
        }
        Integer num = (Integer) c0927x.q.get(c0893n);
        if (num != null) {
            return num.intValue();
        }
        return Integer.MIN_VALUE;
    }

    @Override // androidx.compose.ui.layout.J
    public final int z(int i) {
        InterfaceC0926w interfaceC0926w = this.K;
        a0 a0Var = this.m;
        Intrinsics.d(a0Var);
        return interfaceC0926w.b(this, a0Var, i);
    }
}
