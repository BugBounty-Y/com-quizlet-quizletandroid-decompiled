package androidx.compose.ui.text.font;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.font.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0992f {
    public final A a;

    public C0992f(A a) {
        this.a = a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C0992f) {
            return Intrinsics.b(this.a, ((C0992f) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode() * 31;
    }

    public final String toString() {
        return "Key(font=" + this.a + ", loaderKey=null)";
    }
}
