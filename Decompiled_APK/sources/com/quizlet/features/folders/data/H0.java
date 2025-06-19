package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H0 {
    public final K0 a;
    public final Integer b;
    public final boolean c;

    public H0(K0 option, Integer num, boolean z) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
        this.b = num;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H0)) {
            return false;
        }
        H0 h0 = (H0) obj;
        return this.a.equals(h0.a) && Intrinsics.b(this.b, h0.b) && this.c == h0.c;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Integer num = this.b;
        return Boolean.hashCode(this.c) + ((iHashCode + (num == null ? 0 : num.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MenuOption(option=");
        sb.append(this.a);
        sb.append(", iconRes=");
        sb.append(this.b);
        sb.append(", isSelected=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
