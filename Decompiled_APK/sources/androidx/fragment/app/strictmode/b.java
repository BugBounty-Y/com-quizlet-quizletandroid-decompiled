package androidx.fragment.app.strictmode;

import java.util.LinkedHashMap;
import kotlin.collections.J;
import kotlin.collections.L;
import kotlin.collections.M;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public static final b b = new b(M.a, V.c());
    public final M a;

    public b(M flags, L allowedViolations) {
        Intrinsics.checkNotNullParameter(flags, "flags");
        Intrinsics.checkNotNullParameter(allowedViolations, "allowedViolations");
        this.a = flags;
        new LinkedHashMap();
        M.a.getClass();
        J.a.getClass();
    }
}
