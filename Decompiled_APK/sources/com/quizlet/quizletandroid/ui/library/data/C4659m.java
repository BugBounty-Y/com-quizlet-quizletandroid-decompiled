package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4659m implements p {
    public final int a;
    public final com.quizlet.library.data.d b;

    public C4659m(int i, com.quizlet.library.data.d item) {
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
        if (!(obj instanceof C4659m)) {
            return false;
        }
        C4659m c4659m = (C4659m) obj;
        return this.a == c4659m.a && Intrinsics.b(this.b, c4659m.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "Notes(position=" + this.a + ", item=" + this.b + ")";
    }
}
