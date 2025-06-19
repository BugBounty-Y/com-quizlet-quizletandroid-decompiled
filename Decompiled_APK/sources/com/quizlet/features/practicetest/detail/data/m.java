package com.quizlet.features.practicetest.detail.data;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class m implements p {
    public final int a;
    public final boolean b;
    public final boolean c;

    public m(int i, boolean z, boolean z2) {
        this.a = i;
        this.b = z;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return this.a == mVar.a && this.b == mVar.b && this.c == mVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Integer.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TakeTestConfigurationButtonClicked(questionCount=");
        sb.append(this.a);
        sb.append(", isMultipleChoiceSelected=");
        sb.append(this.b);
        sb.append(", isWrittenSelected=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
