package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.practicetest.takingtest.data.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4414h implements InterfaceC4415i {
    public final String a;

    public C4414h(String answer) {
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = answer;
    }

    @Override // com.quizlet.features.practicetest.takingtest.data.InterfaceC4415i
    public final boolean a() {
        return this.a.length() > 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4414h) && Intrinsics.b(this.a, ((C4414h) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Written(answer="), this.a, ")");
    }
}
