package androidx.compose.ui.node;

import androidx.compose.ui.layout.C0893n;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.node.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0927x extends P {
    public final /* synthetic */ C0928y r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0927x(C0928y c0928y) {
        super(c0928y);
        this.r = c0928y;
    }

    @Override // androidx.compose.ui.layout.J
    public final androidx.compose.ui.layout.W B(long j) {
        x0(j);
        new androidx.compose.ui.unit.a(j);
        C0928y c0928y = this.r;
        c0928y.getClass();
        InterfaceC0926w interfaceC0926w = c0928y.K;
        a0 a0Var = c0928y.m;
        Intrinsics.d(a0Var);
        P pU0 = a0Var.U0();
        Intrinsics.d(pU0);
        P.K0(this, interfaceC0926w.h(this, pU0, j));
        return this;
    }

    @Override // androidx.compose.ui.layout.J
    public final int X(int i) {
        C0928y c0928y = this.r;
        InterfaceC0926w interfaceC0926w = c0928y.K;
        a0 a0Var = c0928y.m;
        Intrinsics.d(a0Var);
        P pU0 = a0Var.U0();
        Intrinsics.d(pU0);
        return interfaceC0926w.f(this, pU0, i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int b(int i) {
        C0928y c0928y = this.r;
        InterfaceC0926w interfaceC0926w = c0928y.K;
        a0 a0Var = c0928y.m;
        Intrinsics.d(a0Var);
        P pU0 = a0Var.U0();
        Intrinsics.d(pU0);
        return interfaceC0926w.i(this, pU0, i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int x(int i) {
        C0928y c0928y = this.r;
        InterfaceC0926w interfaceC0926w = c0928y.K;
        a0 a0Var = c0928y.m;
        Intrinsics.d(a0Var);
        P pU0 = a0Var.U0();
        Intrinsics.d(pU0);
        return interfaceC0926w.c(this, pU0, i);
    }

    @Override // androidx.compose.ui.node.O
    public final int y0(C0893n c0893n) {
        int iC = AbstractC0910f.c(this, c0893n);
        this.q.put(c0893n, Integer.valueOf(iC));
        return iC;
    }

    @Override // androidx.compose.ui.layout.J
    public final int z(int i) {
        C0928y c0928y = this.r;
        InterfaceC0926w interfaceC0926w = c0928y.K;
        a0 a0Var = c0928y.m;
        Intrinsics.d(a0Var);
        P pU0 = a0Var.U0();
        Intrinsics.d(pU0);
        return interfaceC0926w.b(this, pU0, i);
    }
}
