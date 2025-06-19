package androidx.compose.foundation.lazy.layout;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class c0 {
    public final kotlin.jvm.internal.r a;
    public final p0 b;
    public com.quizlet.data.interactor.set.c c;

    /* JADX WARN: Multi-variable type inference failed */
    public c0(Function1 function1) {
        this.a = (kotlin.jvm.internal.r) function1;
        p0 p0Var = new p0();
        int i = androidx.collection.Q.a;
        p0Var.c = new androidx.collection.H(6);
        p0Var.d = new androidx.collection.H(6);
        this.b = p0Var;
    }

    public final b0 a(int i, long j) {
        com.quizlet.data.interactor.set.c cVar = this.c;
        if (cVar == null) {
            return C0434f.a;
        }
        o0 o0Var = new o0(cVar, i, j, this.b);
        ((q0) cVar.c).c(o0Var);
        return o0Var;
    }
}
