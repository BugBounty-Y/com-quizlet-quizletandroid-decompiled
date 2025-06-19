package androidx.compose.foundation.layout;

import androidx.compose.ui.layout.C0893n;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0376b {
    public final C0893n a;

    public C0376b(C0893n c0893n) {
        this.a = c0893n;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C0376b) && Intrinsics.b(this.a, ((C0376b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Value(alignmentLine=" + this.a + ')';
    }
}
