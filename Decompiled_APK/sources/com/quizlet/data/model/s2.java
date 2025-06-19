package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class s2 implements t2 {
    public final String a;
    public final boolean b;

    public s2(String text, boolean z) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s2)) {
            return false;
        }
        s2 s2Var = (s2) obj;
        return Intrinsics.b(this.a, s2Var.a) && this.b == s2Var.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Text(text=" + this.a + ", isPrivate=" + this.b + ")";
    }
}
