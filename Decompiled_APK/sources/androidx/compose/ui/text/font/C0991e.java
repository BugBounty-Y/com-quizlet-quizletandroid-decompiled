package androidx.compose.ui.text.font;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.font.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0991e {
    public final Object a;

    public final boolean equals(Object obj) {
        if (obj instanceof C0991e) {
            return Intrinsics.b(this.a, ((C0991e) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        Object obj = this.a;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return "AsyncTypefaceResult(result=" + this.a + ')';
    }
}
