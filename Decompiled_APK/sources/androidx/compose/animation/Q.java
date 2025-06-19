package androidx.compose.animation;

import androidx.compose.animation.core.x0;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class Q extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ a0 b;
    public final /* synthetic */ b0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Q(a0 a0Var, b0 b0Var, int i) {
        super(1);
        this.a = i;
        this.b = a0Var;
        this.c = b0Var;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.animation.core.D d;
        androidx.compose.animation.core.D d2;
        switch (this.a) {
            case 0:
                x0 x0Var = (x0) obj;
                O o = O.a;
                O o2 = O.b;
                if (x0Var.b(o, o2)) {
                    c0 c0Var = this.b.a.a;
                    return (c0Var == null || (d2 = c0Var.b) == null) ? V.b : d2;
                }
                if (!x0Var.b(o2, O.c)) {
                    return V.b;
                }
                c0 c0Var2 = this.c.a.a;
                return (c0Var2 == null || (d = c0Var2.b) == null) ? V.b : d;
            case 1:
                int iOrdinal = ((O) obj).ordinal();
                float f = 1.0f;
                if (iOrdinal == 0) {
                    c0 c0Var3 = this.b.a.a;
                    if (c0Var3 != null) {
                        f = c0Var3.a;
                    }
                } else if (iOrdinal != 1) {
                    if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    c0 c0Var4 = this.c.a.a;
                    if (c0Var4 != null) {
                        f = c0Var4.a;
                    }
                }
                return Float.valueOf(f);
            case 2:
                x0 x0Var2 = (x0) obj;
                O o3 = O.a;
                O o4 = O.b;
                if (!x0Var2.b(o3, o4) && x0Var2.b(o4, O.c)) {
                    q0 q0Var = this.c.a;
                    return V.b;
                }
                return V.b;
            default:
                int iOrdinal2 = ((O) obj).ordinal();
                if (iOrdinal2 != 0 && iOrdinal2 != 1) {
                    if (iOrdinal2 != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    q0 q0Var2 = this.c.a;
                }
                return Float.valueOf(1.0f);
        }
    }
}
