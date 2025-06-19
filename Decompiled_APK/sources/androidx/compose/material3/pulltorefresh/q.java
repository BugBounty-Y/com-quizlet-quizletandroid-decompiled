package androidx.compose.material3.pulltorefresh;

import androidx.compose.animation.core.C0238e;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class q {
    public static final com.quizlet.data.repository.explanations.myexplanations.a b;
    public final C0238e a;

    static {
        p pVar = p.a;
        d dVar = d.c;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
        b = new com.quizlet.data.repository.explanations.myexplanations.a(pVar, false, dVar, 3);
    }

    public q(C0238e c0238e) {
        this.a = c0238e;
    }

    public final Object a(float f, kotlin.coroutines.jvm.internal.i iVar) {
        Object objF = this.a.f(new Float(f), iVar);
        return objF == kotlin.coroutines.intrinsics.a.a ? objF : Unit.a;
    }
}
