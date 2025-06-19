package androidx.compose.ui.input.pointer;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.input.pointer.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0878a implements j {
    public final int b;

    public C0878a(int i) {
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!C0878a.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.AndroidPointerIconType");
        return this.b == ((C0878a) obj).b;
    }

    public final int hashCode() {
        return this.b;
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("AndroidPointerIcon(type="), this.b, ')');
    }
}
