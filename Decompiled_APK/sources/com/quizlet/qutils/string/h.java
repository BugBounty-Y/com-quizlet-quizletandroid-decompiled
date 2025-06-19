package com.quizlet.qutils.string;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final String a;
    public final int b;

    public h(String string, int i) {
        Intrinsics.checkNotNullParameter(string, "string");
        this.a = string;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && this.b == hVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ColoredString(string=" + this.a + ", resolvedColor=" + this.b + ")";
    }
}
