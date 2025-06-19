package androidx.compose.ui.text.font;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.A0;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.C5041z;

/* loaded from: classes.dex */
public final class p {
    public static final o c = new o(C5041z.a, 0);
    public final com.quizlet.data.repository.login.a a;
    public final kotlinx.coroutines.internal.d b;

    public p(com.quizlet.data.repository.login.a aVar) {
        kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
        this.a = aVar;
        CoroutineContext coroutineContextPlus = c.plus(androidx.compose.ui.text.platform.g.a).plus(nVar);
        C5023i0 key = C5023i0.a;
        nVar.getClass();
        Intrinsics.checkNotNullParameter(key, "key");
        this.b = kotlinx.coroutines.E.c(coroutineContextPlus.plus(new A0(null)));
    }
}
