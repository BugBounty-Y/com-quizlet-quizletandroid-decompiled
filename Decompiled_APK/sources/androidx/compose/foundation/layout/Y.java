package androidx.compose.foundation.layout;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Y extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlin.jvm.internal.J b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Y(kotlin.jvm.internal.J j, int i) {
        super(1);
        this.a = i;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                this.b.a = (androidx.compose.ui.layout.W) obj;
                return Unit.a;
            case 1:
                this.b.a = (androidx.compose.ui.layout.W) obj;
                return Unit.a;
            case 2:
                androidx.compose.ui.node.q0 q0Var = (androidx.compose.ui.node.q0) obj;
                Intrinsics.e(q0Var, "null cannot be cast to non-null type androidx.compose.foundation.lazy.layout.TraversablePrefetchStateNode");
                androidx.compose.foundation.lazy.layout.c0 c0Var = ((androidx.compose.foundation.lazy.layout.s0) q0Var).n;
                kotlin.jvm.internal.J j = this.b;
                List listK = (List) j.a;
                if (listK != null) {
                    listK.add(c0Var);
                } else {
                    listK = kotlin.collections.B.k(c0Var);
                }
                j.a = listK;
                return androidx.compose.ui.node.p0.b;
            default:
                androidx.compose.ui.input.pointer.h hVar = (androidx.compose.ui.input.pointer.h) obj;
                kotlin.jvm.internal.J j2 = this.b;
                Object obj2 = j2.a;
                if (obj2 == null && hVar.o) {
                    j2.a = hVar;
                } else if (obj2 != null) {
                    hVar.getClass();
                }
                return Boolean.TRUE;
        }
    }
}
