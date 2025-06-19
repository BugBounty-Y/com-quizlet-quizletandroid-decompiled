package io.ktor.utils.io;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes3.dex */
public final class f implements e {
    public final C5028l b;

    public f(C5028l continuation) {
        Intrinsics.checkNotNullParameter(continuation, "continuation");
        this.b = continuation;
    }

    @Override // io.ktor.utils.io.e
    public final void a(Throwable th) {
        Object objB;
        kotlin.coroutines.h hVarC = c();
        if (th != null) {
            kotlin.p pVar = kotlin.r.b;
            objB = Z.b(th);
        } else {
            g.a.getClass();
            objB = C4881b.c;
        }
        ((C5028l) hVarC).resumeWith(objB);
    }

    @Override // io.ktor.utils.io.e
    public final void b() {
        kotlin.coroutines.h hVarC = c();
        g.a.getClass();
        ((C5028l) hVarC).resumeWith(C4881b.c);
    }

    public final kotlin.coroutines.h c() {
        return this.b;
    }
}
