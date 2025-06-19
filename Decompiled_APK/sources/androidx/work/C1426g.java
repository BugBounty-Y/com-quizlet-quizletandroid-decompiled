package androidx.work;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* renamed from: androidx.work.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1426g extends AbstractC5040y {
    public static final C1426g b = new C1426g();
    public static final kotlinx.coroutines.scheduling.e c = kotlinx.coroutines.O.a;

    @Override // kotlinx.coroutines.AbstractC5040y
    public final boolean a0(CoroutineContext context) {
        Intrinsics.checkNotNullParameter(context, "context");
        c.getClass();
        return !false;
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext context, Runnable block) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(block, "block");
        c.r(context, block);
    }
}
