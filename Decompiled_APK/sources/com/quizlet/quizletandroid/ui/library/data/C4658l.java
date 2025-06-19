package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4658l implements p {
    public final int a;
    public final C4649c b;

    public C4658l(int i, C4649c item) {
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
        if (!(obj instanceof C4658l)) {
            return false;
        }
        C4658l c4658l = (C4658l) obj;
        return this.a == c4658l.a && Intrinsics.b(this.b, c4658l.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "Folder(position=" + this.a + ", item=" + this.b + ")";
    }
}
