package com.quizlet.features.flashcards.logging;

import androidx.compose.animation.d0;

/* loaded from: classes2.dex */
public final class c {
    public final long a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;

    public c(long j, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6) {
        this.a = j;
        this.b = z;
        this.c = z2;
        this.d = z3;
        this.e = z4;
        this.f = z5;
        this.g = z6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b && this.c == cVar.c && this.d == cVar.d && this.e == cVar.e && this.f == cVar.f && this.g == cVar.g;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.g) + d0.g(d0.g(d0.g(d0.g(d0.g(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsQuestionLoggingData(termId=");
        sb.append(this.a);
        sb.append(", hasPromptText=");
        sb.append(this.b);
        sb.append(", hasPromptImage=");
        sb.append(this.c);
        sb.append(", hasPromptAudio=");
        sb.append(this.d);
        sb.append(", hasAnswerText=");
        sb.append(this.e);
        sb.append(", hasAnswerImage=");
        sb.append(this.f);
        sb.append(", hasAnswerAudio=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}
