package androidx.compose.foundation.gestures;

import kotlin.jvm.internal.Intrinsics;
import kotlin.text.CharsKt;
import kotlinx.coroutines.C5028l;

/* renamed from: androidx.compose.foundation.gestures.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0327h {
    public final androidx.compose.foundation.relocation.f a;
    public final C5028l b;

    public C0327h(androidx.compose.foundation.relocation.f fVar, C5028l c5028l) {
        this.a = fVar;
        this.b = c5028l;
    }

    public final String toString() {
        String strB;
        C5028l c5028l = this.b;
        kotlinx.coroutines.B b = (kotlinx.coroutines.B) c5028l.e.get(kotlinx.coroutines.B.b);
        String str = b != null ? b.a : null;
        StringBuilder sb = new StringBuilder("Request@");
        String string = Integer.toString(hashCode(), CharsKt.checkRadix(16));
        Intrinsics.checkNotNullExpressionValue(string, "toString(this, checkRadix(radix))");
        sb.append(string);
        if (str == null || (strB = android.support.v4.media.session.a.B("[", str, "](")) == null) {
            strB = "(";
        }
        sb.append(strB);
        sb.append("currentBounds()=");
        sb.append(this.a.invoke());
        sb.append(", continuation=");
        sb.append(c5028l);
        sb.append(')');
        return sb.toString();
    }
}
