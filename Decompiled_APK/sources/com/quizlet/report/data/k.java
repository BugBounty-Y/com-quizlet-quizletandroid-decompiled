package com.quizlet.report.data;

import com.quizlet.generated.enums.Q0;
import java.util.List;
import kotlin.collections.B;

/* loaded from: classes3.dex */
public final class k implements n {
    public static final k a = new k();
    public static final List b = B.j(new a(Q0.INACCURATE, 2), new a(Q0.UNHELPFUL, 2), new a(Q0.BAD_LANGUAGE, 2), new a(Q0.MATURE, 2), new a(Q0.HARASS_BULLY_OR_HATE, 2), new a(Q0.INTELLECTUAL_PROPERTY, 2));

    @Override // com.quizlet.report.data.n
    public final List a() {
        return b;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof k);
    }

    public final int hashCode() {
        return 1787125271;
    }

    public final String toString() {
        return "MagicNotes";
    }
}
