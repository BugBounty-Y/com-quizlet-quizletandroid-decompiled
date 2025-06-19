package androidx.compose.foundation.pager;

import androidx.compose.runtime.H0;
import androidx.compose.runtime.L0;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class D extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ E b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ D(E e, int i) {
        super(0);
        this.a = i;
        this.b = e;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        int i;
        switch (this.a) {
            case 0:
                E e = this.b;
                return Integer.valueOf(e.j.a() ? e.s.i() : e.j());
            default:
                E e2 = this.b;
                if (e2.j.a()) {
                    H0 h0 = e2.r;
                    i = h0.i() != -1 ? h0.i() : Math.abs(e2.c.j()) >= Math.abs(Math.min(e2.p.c0(I.a), ((float) e2.m()) / 2.0f) / ((float) e2.m())) ? ((Boolean) ((L0) e2.F).getValue()).booleanValue() ? e2.d + 1 : e2.d : e2.j();
                } else {
                    i = e2.j();
                }
                return Integer.valueOf(e2.i(i));
        }
    }
}
