package com.quizlet.remote.model.selectedterm;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteUnselectedTerm implements a {
    public final long a;
    public final long b;
    public final boolean c;

    public RemoteUnselectedTerm(long j, long j2, boolean z) {
        this.a = j;
        this.b = j2;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteUnselectedTerm)) {
            return false;
        }
        RemoteUnselectedTerm remoteUnselectedTerm = (RemoteUnselectedTerm) obj;
        return this.a == remoteUnselectedTerm.a && this.b == remoteUnselectedTerm.b && this.c == remoteUnselectedTerm.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.d(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteUnselectedTerm(termId=");
        sb.append(this.a);
        sb.append(", personId=");
        sb.append(this.b);
        sb.append(", isDeleted=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
