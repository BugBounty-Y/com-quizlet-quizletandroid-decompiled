package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.quizlet.generated.enums.S0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class L {
    public final S0 a;
    public final Integer b;

    public L(S0 type, Integer num) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = type;
        this.b = num;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L)) {
            return false;
        }
        L l = (L) obj;
        return this.a == l.a && Intrinsics.b(this.b, l.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Integer num = this.b;
        return iHashCode + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        return "RevisionCenter(type=" + this.a + ", daysLeft=" + this.b + ")";
    }
}
