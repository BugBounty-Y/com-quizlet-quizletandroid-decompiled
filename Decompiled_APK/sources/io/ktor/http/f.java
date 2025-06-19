package io.ktor.http;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3162h7;
import java.util.Set;
import kotlin.collections.M;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements s {
    public static final f c = new f();

    @Override // io.ktor.util.l
    public final Set a() {
        return M.a;
    }

    @Override // io.ktor.util.l
    public final void b(Function2 body) {
        Intrinsics.checkNotNullParameter(body, "body");
        AbstractC3162h7.c(this, body);
    }

    @Override // io.ktor.util.l
    public final boolean c() {
        return true;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof s) && ((s) obj).isEmpty();
    }

    @Override // io.ktor.util.l
    public final boolean isEmpty() {
        return true;
    }

    public final String toString() {
        return "Parameters " + M.a;
    }
}
