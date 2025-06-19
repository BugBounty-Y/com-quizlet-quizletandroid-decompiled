package com.quizlet.features.practicetest.detail.data;

import androidx.compose.animation.d0;

/* renamed from: com.quizlet.features.practicetest.detail.data.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4405h implements p {
    public final int a;
    public final boolean b;
    public final boolean c;

    public C4405h(int i, boolean z, boolean z2) {
        this.a = i;
        this.b = z;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4405h)) {
            return false;
        }
        C4405h c4405h = (C4405h) obj;
        return this.a == c4405h.a && this.b == c4405h.b && this.c == c4405h.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Integer.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SaveConfiguration(questionCount=");
        sb.append(this.a);
        sb.append(", isMultipleChoiceSelected=");
        sb.append(this.b);
        sb.append(", isWrittenSelected=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
