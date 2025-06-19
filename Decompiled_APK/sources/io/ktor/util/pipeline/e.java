package io.ktor.util.pipeline;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public abstract class e implements C {
    public final Object a;

    public e(Object context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    public abstract Object a(Object obj, kotlin.coroutines.jvm.internal.c cVar);

    public abstract Object b();

    public abstract Object c(kotlin.coroutines.h hVar);

    public abstract Object d(Object obj, kotlin.coroutines.h hVar);
}
