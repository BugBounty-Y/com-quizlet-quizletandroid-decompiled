package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0511o extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ N0 b;
    public final /* synthetic */ Function1 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0511o(N0 n0, Function1 function1, int i) {
        super(1);
        this.a = i;
        this.b = n0;
        this.c = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.text.H h = (androidx.compose.ui.text.H) obj;
                N0 n0 = this.b;
                if (n0 != null) {
                    ((androidx.compose.runtime.L0) n0.b).setValue(h);
                }
                Function1 function1 = this.c;
                if (function1 != null) {
                    function1.invoke(h);
                }
                return Unit.a;
            default:
                N0 n02 = this.b;
                androidx.compose.runtime.snapshots.q qVar = n02.d;
                Function1 function12 = this.c;
                qVar.add(function12);
                return new androidx.compose.animation.core.P(7, n02, function12);
        }
    }
}
