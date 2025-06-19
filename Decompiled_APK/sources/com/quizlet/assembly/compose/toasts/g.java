package com.quizlet.assembly.compose.toasts;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class g {
    public final long a;
    public final InterfaceC0773a0 b;

    public g(long j) {
        InterfaceC0773a0 shouldShow = C0776c.z(Boolean.FALSE);
        Intrinsics.checkNotNullParameter(shouldShow, "shouldShow");
        this.a = j;
        this.b = shouldShow;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ToastState(duration=" + this.a + ", shouldShow=" + this.b + ")";
    }
}
