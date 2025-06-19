package androidx.compose.foundation.lazy.layout;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class g0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g0(i0 i0Var, int i) {
        super(1);
        this.a = i;
        this.b = i0Var;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                N n = (N) this.b.n.invoke();
                int iD = n.d();
                int i = 0;
                while (true) {
                    if (i >= iD) {
                        i = -1;
                    } else if (!n.b(i).equals(obj)) {
                        i++;
                    }
                }
                return Integer.valueOf(i);
            default:
                int iIntValue = ((Number) obj).intValue();
                i0 i0Var = this.b;
                N n2 = (N) i0Var.n.invoke();
                if (iIntValue >= 0 && iIntValue < n2.d()) {
                    kotlinx.coroutines.E.A(i0Var.A0(), null, null, new h0(i0Var, iIntValue, null), 3);
                    return Boolean.TRUE;
                }
                StringBuilder sbV = android.support.v4.media.session.a.v(iIntValue, "Can't scroll to index ", ", it is out of bounds [0, ");
                sbV.append(n2.d());
                sbV.append(')');
                throw new IllegalArgumentException(sbV.toString().toString());
        }
    }
}
