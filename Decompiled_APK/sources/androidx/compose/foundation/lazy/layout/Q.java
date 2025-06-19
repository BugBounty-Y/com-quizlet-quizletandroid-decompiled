package androidx.compose.foundation.lazy.layout;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class Q extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ c0 a;
    public final /* synthetic */ M b;
    public final /* synthetic */ androidx.compose.ui.layout.e0 c;
    public final /* synthetic */ q0 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(c0 c0Var, M m, androidx.compose.ui.layout.e0 e0Var, q0 q0Var) {
        super(1);
        this.a = c0Var;
        this.b = m;
        this.c = e0Var;
        this.d = q0Var;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c(this.b, this.c, this.d);
        c0 c0Var = this.a;
        c0Var.c = cVar;
        return new androidx.activity.compose.c(c0Var, 4);
    }
}
