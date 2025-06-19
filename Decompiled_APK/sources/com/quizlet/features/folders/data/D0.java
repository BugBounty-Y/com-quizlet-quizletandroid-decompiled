package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D0 {
    public final int a;
    public final int b;
    public final boolean c;
    public final Integer d;

    public D0(int i, int i2, boolean z, Integer num) {
        this.a = i;
        this.b = i2;
        this.c = z;
        this.d = num;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D0)) {
            return false;
        }
        D0 d0 = (D0) obj;
        return this.a == d0.a && this.b == d0.b && this.c == d0.c && Intrinsics.b(this.d, d0.d);
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31, this.c);
        Integer num = this.d;
        return iG + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Button(res=");
        sb.append(this.a);
        sb.append(", iconRes=");
        sb.append(this.b);
        sb.append(", iconIsActive=");
        sb.append(this.c);
        sb.append(", iconContentDescription=");
        return assistantMode.refactored.a.l(sb, this.d, ")");
    }
}
