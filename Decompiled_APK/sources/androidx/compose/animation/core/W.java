package androidx.compose.animation.core;

import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class W {
    public final AtomicReference a = new AtomicReference(null);
    public final kotlinx.coroutines.sync.c b = kotlinx.coroutines.sync.d.a();

    public static Object a(W w, Function1 function1, kotlin.coroutines.h hVar) {
        w.getClass();
        return kotlinx.coroutines.E.m(new V(w, function1, null), hVar);
    }
}
