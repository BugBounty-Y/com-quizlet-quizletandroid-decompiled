package androidx.compose.animation;

import androidx.compose.animation.core.x0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class Y extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Z b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Y(Z z, int i) {
        super(1);
        this.a = i;
        this.b = z;
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
                boolean zB = x0Var.b(o, o2);
                Object obj2 = null;
                Z z = this.b;
                if (zB) {
                    I i = z.s.a.c;
                    if (i != null) {
                        obj2 = i.c;
                    }
                } else if (x0Var.b(o2, O.c)) {
                    I i2 = z.t.a.c;
                    if (i2 != null) {
                        obj2 = i2.c;
                    }
                } else {
                    obj2 = V.d;
                }
                return obj2 == null ? V.d : obj2;
            default:
                x0 x0Var2 = (x0) obj;
                O o3 = O.a;
                O o4 = O.b;
                boolean zB2 = x0Var2.b(o3, o4);
                Z z2 = this.b;
                if (zB2) {
                    o0 o0Var = z2.s.a.b;
                    return (o0Var == null || (d2 = o0Var.b) == null) ? V.c : d2;
                }
                if (!x0Var2.b(o4, O.c)) {
                    return V.c;
                }
                o0 o0Var2 = z2.t.a.b;
                return (o0Var2 == null || (d = o0Var2.b) == null) ? V.c : d;
        }
    }
}
