package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.x1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4180x1 {
    public final List a;
    public final String b;

    public C4180x1(String searchSessionId, List schools) {
        Intrinsics.checkNotNullParameter(schools, "schools");
        Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
        this.a = schools;
        this.b = searchSessionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4180x1)) {
            return false;
        }
        C4180x1 c4180x1 = (C4180x1) obj;
        return Intrinsics.b(this.a, c4180x1.a) && Intrinsics.b(this.b, c4180x1.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SchoolSearchResults(schools=" + this.a + ", searchSessionId=" + this.b + ")";
    }
}
