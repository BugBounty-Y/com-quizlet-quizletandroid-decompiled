package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements p {
    public final int a;
    public final com.quizlet.library.viewmodels.e b;

    public n(int i, com.quizlet.library.viewmodels.e item) {
        Intrinsics.checkNotNullParameter(item, "item");
        this.a = i;
        this.b = item;
    }

    @Override // com.quizlet.quizletandroid.ui.library.data.p
    public final int a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return this.a == nVar.a && Intrinsics.b(this.b, nVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "PracticeTest(position=" + this.a + ", item=" + this.b + ")";
    }
}
