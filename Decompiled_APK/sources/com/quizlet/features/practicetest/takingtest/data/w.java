package com.quizlet.features.practicetest.takingtest.data;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class w implements y {
    public final int a;
    public final boolean b;
    public final boolean c;

    public w(int i, boolean z, boolean z2) {
        this.a = i;
        this.b = z;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w)) {
            return false;
        }
        w wVar = (w) obj;
        return this.a == wVar.a && this.b == wVar.b && this.c == wVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Integer.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TakeTestClicked(questionCount=");
        sb.append(this.a);
        sb.append(", isMultipleChoiceSelected=");
        sb.append(this.b);
        sb.append(", isWrittenSelected=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
