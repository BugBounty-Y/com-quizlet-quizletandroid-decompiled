package com.quizlet.shared.models.api.keys;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final String b;
    public final String c;

    public a(String submittedAnswer, String expectedAnswer, String languageCode) {
        Intrinsics.checkNotNullParameter(submittedAnswer, "submittedAnswer");
        Intrinsics.checkNotNullParameter(expectedAnswer, "expectedAnswer");
        Intrinsics.checkNotNullParameter(languageCode, "languageCode");
        this.a = submittedAnswer;
        this.b = expectedAnswer;
        this.c = languageCode;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LongtextGradingResultKey(submittedAnswer=");
        sb.append(this.a);
        sb.append(", expectedAnswer=");
        sb.append(this.b);
        sb.append(", languageCode=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
