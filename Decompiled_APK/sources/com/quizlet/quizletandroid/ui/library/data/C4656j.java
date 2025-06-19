package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4656j implements p {
    public final int a;
    public final com.quizlet.library.viewmodels.a b;

    public C4656j(int i, com.quizlet.library.viewmodels.a item) {
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
        if (!(obj instanceof C4656j)) {
            return false;
        }
        C4656j c4656j = (C4656j) obj;
        return this.a == c4656j.a && Intrinsics.b(this.b, c4656j.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ExpertSolution(position=" + this.a + ", item=" + this.b + ")";
    }
}
