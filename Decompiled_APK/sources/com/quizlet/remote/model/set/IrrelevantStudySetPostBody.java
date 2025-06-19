package com.quizlet.remote.model.set;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class IrrelevantStudySetPostBody {
    public final int a;
    public final int b;
    public final int c;
    public final long d;

    public IrrelevantStudySetPostBody(long j, int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof IrrelevantStudySetPostBody)) {
            return false;
        }
        IrrelevantStudySetPostBody irrelevantStudySetPostBody = (IrrelevantStudySetPostBody) obj;
        return this.a == irrelevantStudySetPostBody.a && this.b == irrelevantStudySetPostBody.b && this.c == irrelevantStudySetPostBody.c && this.d == irrelevantStudySetPostBody.d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d) + d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("IrrelevantStudySetPostBody(personId=");
        sb.append(this.a);
        sb.append(", modelId=");
        sb.append(this.b);
        sb.append(", modelType=");
        sb.append(this.c);
        sb.append(", created=");
        return android.support.v4.media.session.a.g(this.d, ")", sb);
    }
}
