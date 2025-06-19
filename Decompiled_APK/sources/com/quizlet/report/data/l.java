package com.quizlet.report.data;

import com.quizlet.generated.enums.Q0;
import java.util.List;
import kotlin.collections.B;

/* loaded from: classes3.dex */
public final class l implements n {
    public static final l a = new l();
    public static final List b;

    static {
        a aVar = new a(Q0.DID_NOT_LIKE, 2);
        a aVar2 = new a(Q0.INACCURATE, 2);
        a aVar3 = new a(Q0.UNHELPFUL, 2);
        j jVar = j.a;
        b = B.j(aVar, aVar2, aVar3, new a(null, 1));
    }

    @Override // com.quizlet.report.data.n
    public final List a() {
        return b;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof l);
    }

    public final int hashCode() {
        return -382180462;
    }

    public final String toString() {
        return "McqExplanations";
    }
}
