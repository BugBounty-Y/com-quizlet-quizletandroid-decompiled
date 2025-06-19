package io.ktor.http;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3162h7;
import java.util.Set;
import kotlin.collections.M;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements k {
    public static final e c = new e();

    @Override // io.ktor.util.l
    public final Set a() {
        return M.a;
    }

    @Override // io.ktor.util.l
    public final void b(Function2 function2) {
        com.quizlet.features.settings.composables.dialogs.a body = (com.quizlet.features.settings.composables.dialogs.a) function2;
        Intrinsics.checkNotNullParameter(body, "body");
        AbstractC3162h7.c(this, body);
    }

    @Override // io.ktor.util.l
    public final boolean c() {
        return true;
    }

    @Override // io.ktor.util.l
    public final String d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(name, "name");
        return null;
    }

    public final String toString() {
        return "Headers " + M.a;
    }
}
