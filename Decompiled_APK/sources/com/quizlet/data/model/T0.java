package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class T0 {
    public final String a;
    public final List b;

    public T0(String section, List practiceTestInfoItems) {
        Intrinsics.checkNotNullParameter(section, "section");
        Intrinsics.checkNotNullParameter(practiceTestInfoItems, "practiceTestInfoItems");
        this.a = section;
        this.b = practiceTestInfoItems;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof T0)) {
            return false;
        }
        T0 t0 = (T0) obj;
        return Intrinsics.b(this.a, t0.a) && Intrinsics.b(this.b, t0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "PracticeTestInfoWithSection(section=" + this.a + ", practiceTestInfoItems=" + this.b + ")";
    }
}
