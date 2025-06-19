package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final int a;
    public final n b;

    public a(int i, n bucketState) {
        Intrinsics.checkNotNullParameter(bucketState, "bucketState");
        this.a = i;
        this.b = bucketState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "HeaderState(studyProgress=" + this.a + ", bucketState=" + this.b + ")";
    }
}
