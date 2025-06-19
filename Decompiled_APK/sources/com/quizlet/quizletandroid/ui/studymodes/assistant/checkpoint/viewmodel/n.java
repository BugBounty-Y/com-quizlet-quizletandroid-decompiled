package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public final int a;
    public final o b;
    public final int c;
    public final int d;

    public n(int i, o selectedBucket, int i2, int i3) {
        Intrinsics.checkNotNullParameter(selectedBucket, "selectedBucket");
        this.a = i;
        this.b = selectedBucket;
        this.c = i2;
        this.d = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return this.a == nVar.a && this.b == nVar.b && this.c == nVar.c && this.d == nVar.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + d0.b(this.c, (this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31, 31);
    }

    public final String toString() {
        return "WriteBucketState(studyProgress=" + this.a + ", selectedBucket=" + this.b + ", numIncorrect=" + this.c + ", numCorrect=" + this.d + ")";
    }
}
