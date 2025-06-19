package com.quizlet.report.data;

import com.quizlet.generated.enums.Q0;
import java.util.List;
import kotlin.collections.B;

/* loaded from: classes3.dex */
public final class m implements n {
    public static final m a = new m();
    public static final List b;

    static {
        a aVar = new a(Q0.INACCURATE, 2);
        a aVar2 = new a(Q0.IRRELEVANT, 2);
        a aVar3 = new a(Q0.TOO_EASY_OR_HARD, 2);
        a aVar4 = new a(Q0.CHEATING, 2);
        j jVar = j.a;
        b = B.j(aVar, aVar2, aVar3, aVar4, new a(null, 1), new a(Q0.INTELLECTUAL_PROPERTY, 2));
    }

    @Override // com.quizlet.report.data.n
    public final List a() {
        return b;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof m);
    }

    public final int hashCode() {
        return 176067760;
    }

    public final String toString() {
        return "PracticeTest";
    }
}
