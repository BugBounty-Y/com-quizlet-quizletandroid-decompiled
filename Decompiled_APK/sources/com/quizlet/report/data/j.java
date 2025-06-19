package com.quizlet.report.data;

import com.quizlet.generated.enums.Q0;
import java.util.List;
import kotlin.collections.B;

/* loaded from: classes3.dex */
public final class j implements n {
    public static final j a = new j();
    public static final List b = B.j(new a(Q0.BAD_LANGUAGE, 2), new a(Q0.MATURE, 2), new a(Q0.HARASS_BULLY_OR_HATE, 2));

    @Override // com.quizlet.report.data.n
    public final List a() {
        return b;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof j);
    }

    public final int hashCode() {
        return -305907199;
    }

    public final String toString() {
        return "Inappropriate";
    }
}
