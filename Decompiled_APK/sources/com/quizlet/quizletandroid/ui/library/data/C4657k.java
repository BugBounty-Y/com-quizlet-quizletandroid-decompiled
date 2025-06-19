package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4657k implements p {
    public final int a;
    public final K b;

    public C4657k(int i, K item) {
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
        if (!(obj instanceof C4657k)) {
            return false;
        }
        C4657k c4657k = (C4657k) obj;
        return this.a == c4657k.a && Intrinsics.b(this.b, c4657k.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "FlashcardSet(position=" + this.a + ", item=" + this.b + ")";
    }
}
