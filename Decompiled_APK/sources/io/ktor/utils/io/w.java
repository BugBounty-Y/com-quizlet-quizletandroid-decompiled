package io.ktor.utils.io;

import com.google.android.gms.internal.mlkit_vision_camera.G1;
import com.quizlet.search.composables.E;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.y0;

/* loaded from: classes3.dex */
public abstract class w {
    public static final u a = new u();

    public static final void a(t tVar, Throwable th) throws Throwable {
        Intrinsics.checkNotNullParameter(tVar, "<this>");
        if (th != null) {
            ((k) tVar).b(th);
            return;
        }
        E e = new E(1, tVar, t.class, "flushAndClose", "flushAndClose(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", 0, 12);
        Intrinsics.checkNotNullParameter(e, "<this>");
        u completion = a;
        try {
            Intrinsics.checkNotNullParameter(e, "<this>");
            Intrinsics.checkNotNullParameter(completion, "completion");
            Intrinsics.checkNotNullParameter(completion, "completion");
            kotlin.coroutines.n nVar = completion.a;
            kotlin.coroutines.h hVarB = kotlin.coroutines.intrinsics.h.b(nVar == kotlin.coroutines.n.a ? new kotlin.coroutines.intrinsics.b(completion, e) : new kotlin.coroutines.intrinsics.c(completion, nVar, e));
            kotlin.p pVar = kotlin.r.b;
            kotlinx.coroutines.internal.b.g(Unit.a, hVarB);
        } catch (Throwable th2) {
            G1.f(th2, completion);
            throw null;
        }
    }

    public static A b(C c, CoroutineContext coroutineContext, Function2 block, int i) {
        if ((i & 1) != 0) {
            coroutineContext = kotlin.coroutines.n.a;
        }
        Intrinsics.checkNotNullParameter(c, "<this>");
        Intrinsics.checkNotNullParameter(coroutineContext, "coroutineContext");
        Intrinsics.checkNotNullParameter(block, "block");
        k channel = new k();
        Intrinsics.checkNotNullParameter(c, "<this>");
        Intrinsics.checkNotNullParameter(coroutineContext, "coroutineContext");
        Intrinsics.checkNotNullParameter(channel, "channel");
        Intrinsics.checkNotNullParameter(block, "block");
        y0 y0VarA = kotlinx.coroutines.E.A(c, coroutineContext, null, new v(block, channel, null), 2);
        y0VarA.Q(new com.quizlet.ui.compose.modifiers.b(channel, 10));
        return new A(channel, y0VarA);
    }
}
