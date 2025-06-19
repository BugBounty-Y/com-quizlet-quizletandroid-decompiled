package com.quizlet.explanations.textbook.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class m extends p {
    public final String a;
    public final boolean b;

    public m(String tag, boolean z) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        this.a = tag;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && this.b == mVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ChapterMenu(tag=" + this.a + ", isPremiumTextbook=" + this.b + ")";
    }
}
