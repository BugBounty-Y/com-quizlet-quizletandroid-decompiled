package com.quizlet.remote.model.selectedterm;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSelectedTerm implements a {
    public final long a;
    public final long b;
    public final long c;
    public final int d;

    public RemoteSelectedTerm(long j, long j2, int i, long j3) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSelectedTerm)) {
            return false;
        }
        RemoteSelectedTerm remoteSelectedTerm = (RemoteSelectedTerm) obj;
        return this.a == remoteSelectedTerm.a && this.b == remoteSelectedTerm.b && this.c == remoteSelectedTerm.c && this.d == remoteSelectedTerm.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteSelectedTerm(termId=");
        sb.append(this.a);
        sb.append(", personId=");
        sb.append(this.b);
        sb.append(", setId=");
        sb.append(this.c);
        sb.append(", source=");
        return android.support.v4.media.session.a.r(sb, this.d, ")");
    }
}
