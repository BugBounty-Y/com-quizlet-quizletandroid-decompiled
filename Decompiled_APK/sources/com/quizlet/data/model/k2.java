package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k2 {
    public final Textbook a;
    public final X b;

    public k2(Textbook textbook, X x) {
        Intrinsics.checkNotNullParameter(textbook, "textbook");
        this.a = textbook;
        this.b = x;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k2)) {
            return false;
        }
        k2 k2Var = (k2) obj;
        return Intrinsics.b(this.a, k2Var.a) && Intrinsics.b(this.b, k2Var.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        X x = this.b;
        return iHashCode + (x == null ? 0 : x.hashCode());
    }

    public final String toString() {
        return "TextbookWithMetering(textbook=" + this.a + ", meteringInfo=" + this.b + ")";
    }
}
