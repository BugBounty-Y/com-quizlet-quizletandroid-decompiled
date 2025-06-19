package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.b1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4112b1 {
    public final String a;
    public final Object b;

    public C4112b1(String option, List list) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
        this.b = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4112b1)) {
            return false;
        }
        C4112b1 c4112b1 = (C4112b1) obj;
        return Intrinsics.b(this.a, c4112b1.a) && Intrinsics.b(this.b, c4112b1.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Object obj = this.b;
        return iHashCode + (obj == null ? 0 : obj.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestsAnswerOption(option=");
        sb.append(this.a);
        sb.append(", images=");
        return android.support.v4.media.session.a.s(sb, this.b, ")");
    }
}
