package androidx.fragment.app;

import android.transition.Transition;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1146n extends AbstractC1139j {
    public final Object b;
    public final boolean c;
    public final Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1146n(H0 operation, boolean z, boolean z2) {
        super(operation);
        Intrinsics.checkNotNullParameter(operation, "operation");
        J0 j0 = operation.a;
        J0 j02 = J0.b;
        Fragment fragment = operation.c;
        this.b = j0 == j02 ? z ? fragment.getReenterTransition() : fragment.getEnterTransition() : z ? fragment.getReturnTransition() : fragment.getExitTransition();
        this.c = operation.a == j02 ? z ? fragment.getAllowReturnTransitionOverlap() : fragment.getAllowEnterTransitionOverlap() : true;
        this.d = z2 ? z ? fragment.getSharedElementReturnTransition() : fragment.getSharedElementEnterTransition() : null;
    }

    public final z0 b() {
        Object obj = this.b;
        z0 z0VarC = c(obj);
        Object obj2 = this.d;
        z0 z0VarC2 = c(obj2);
        if (z0VarC == null || z0VarC2 == null || z0VarC == z0VarC2) {
            return z0VarC == null ? z0VarC2 : z0VarC;
        }
        throw new IllegalArgumentException(("Mixing framework transitions and AndroidX transitions is not allowed. Fragment " + this.a.c + " returned Transition " + obj + " which uses a different Transition  type than its shared element transition " + obj2).toString());
    }

    public final z0 c(Object obj) {
        if (obj == null) {
            return null;
        }
        x0 x0Var = s0.a;
        if (obj instanceof Transition) {
            return x0Var;
        }
        z0 z0Var = s0.b;
        if (z0Var != null && z0Var.g(obj)) {
            return z0Var;
        }
        throw new IllegalArgumentException("Transition " + obj + " for fragment " + this.a.c + " is not a valid framework Transition or AndroidX Transition");
    }
}
