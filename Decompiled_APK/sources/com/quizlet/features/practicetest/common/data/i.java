package com.quizlet.features.practicetest.common.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final int a;
    public final j b;

    public i(int i, j status) {
        Intrinsics.checkNotNullParameter(status, "status");
        this.a = i;
        this.b = status;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && this.b == iVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "PracticeTestQuestionListItem(questionIndex=" + this.a + ", status=" + this.b + ")";
    }
}
