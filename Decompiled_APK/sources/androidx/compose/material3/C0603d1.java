package androidx.compose.material3;

import androidx.compose.ui.node.AbstractC0910f;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.material3.d1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0603d1 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0609e1 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0603d1(C0609e1 c0609e1, int i) {
        super(0);
        this.a = i;
        this.b = c0609e1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        int i = 0;
        C0609e1 c0609e1 = this.b;
        switch (this.a) {
            case 0:
                return Z1.b;
            default:
                if (((C0690n3) AbstractC0910f.i(c0609e1, AbstractC0696o3.b)) == null) {
                    androidx.compose.material.ripple.b bVar = c0609e1.t;
                    if (bVar != null) {
                        c0609e1.N0(bVar);
                    }
                } else if (c0609e1.t == null) {
                    C0597c1 c0597c1 = new C0597c1(c0609e1, 0);
                    C0603d1 c0603d1 = new C0603d1(c0609e1, i);
                    androidx.compose.animation.core.K0 k0 = androidx.compose.material.ripple.k.a;
                    androidx.compose.material.ripple.b bVar2 = new androidx.compose.material.ripple.b(c0609e1.p, c0609e1.q, c0609e1.r, c0597c1, c0603d1);
                    c0609e1.M0(bVar2);
                    c0609e1.t = bVar2;
                }
                return Unit.a;
        }
    }
}
