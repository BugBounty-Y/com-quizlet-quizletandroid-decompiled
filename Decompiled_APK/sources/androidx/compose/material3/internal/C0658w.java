package androidx.compose.material3.internal;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.internal.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0658w {
    public final String a;
    public final char b;
    public final String c;

    public C0658w(String str, char c) {
        this.a = str;
        this.b = c;
        this.c = kotlin.text.D.o(str, String.valueOf(c), "", false);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0658w)) {
            return false;
        }
        C0658w c0658w = (C0658w) obj;
        return Intrinsics.b(this.a, c0658w.a) && this.b == c0658w.b;
    }

    public final int hashCode() {
        return Character.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "DateInputFormat(patternWithDelimiters=" + this.a + ", delimiter=" + this.b + ')';
    }
}
