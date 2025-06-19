package androidx.compose.foundation.lazy.grid;

import androidx.compose.animation.C0292t;
import androidx.compose.animation.E;
import androidx.compose.animation.J;
import androidx.compose.animation.V;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.n0;
import androidx.compose.material3.C0602d0;
import androidx.compose.material3.C0615f1;
import androidx.compose.material3.C0736u;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class w extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ w(int i, int i2) {
        super(1);
        this.a = i2;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                return Integer.valueOf(((u) obj).a - this.b);
            case 1:
                ((Number) obj).intValue();
                return Integer.valueOf(this.b);
            case 2:
                ((Number) obj).intValue();
                return Integer.valueOf(this.b);
            case 3:
                int i = ((C0615f1) ((C0292t) obj).c()).a;
                int i2 = this.b;
                J jL = i == 1 ? E.l(V.h(1).a(V.c(AbstractC0240f.r(100, 100, null, 4), 2)), V.d(AbstractC0240f.r(100, 0, null, 6), 2).a(V.j(1, new w(i2, 1)))) : E.l(V.g(AbstractC0240f.r(0, 50, null, 5), new w(i2, 2)).a(V.c(AbstractC0240f.r(100, 100, null, 4), 2)), V.j(1, C0736u.j).a(V.d(AbstractC0240f.r(100, 0, null, 6), 2)));
                jL.d = new n0(C0602d0.u);
                return jL;
            case 4:
                Boolean boolF = androidx.compose.ui.focus.a.F((androidx.compose.ui.focus.t) obj, this.b);
                return Boolean.valueOf(boolF != null ? boolF.booleanValue() : false);
            default:
                Boolean boolF2 = androidx.compose.ui.focus.a.F((androidx.compose.ui.focus.t) obj, this.b);
                return Boolean.valueOf(boolF2 != null ? boolF2.booleanValue() : false);
        }
    }
}
