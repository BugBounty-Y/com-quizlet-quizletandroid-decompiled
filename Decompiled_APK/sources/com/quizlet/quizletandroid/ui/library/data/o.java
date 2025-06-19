package com.quizlet.quizletandroid.ui.library.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements p {
    public final int a;
    public final C4648b b;

    public o(int i, C4648b item) {
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
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return this.a == oVar.a && Intrinsics.b(this.b, oVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "QClass(position=" + this.a + ", item=" + this.b + ")";
    }
}
