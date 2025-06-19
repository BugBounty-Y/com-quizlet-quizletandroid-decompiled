package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class A2 {
    public final int a;
    public final int b;
    public final EnumC4173v0 c;

    public A2(int i, int i2, EnumC4173v0 label) {
        Intrinsics.checkNotNullParameter(label, "label");
        this.a = i;
        this.b = i2;
        this.c = label;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A2)) {
            return false;
        }
        A2 a2 = (A2) obj;
        return this.a == a2.a && this.b == a2.b && this.c == a2.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + androidx.compose.animation.d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        return "MemoryScore(delay=" + this.a + ", score=" + this.b + ", label=" + this.c + ")";
    }
}
