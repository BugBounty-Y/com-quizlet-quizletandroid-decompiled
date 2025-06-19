package com.quizlet.remote.model.selectedterm;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SelectedTermRequest {
    public final long a;
    public final long b;
    public final long c;
    public final int d;

    public SelectedTermRequest(long j, long j2, int i, long j3) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SelectedTermRequest)) {
            return false;
        }
        SelectedTermRequest selectedTermRequest = (SelectedTermRequest) obj;
        return this.a == selectedTermRequest.a && this.b == selectedTermRequest.b && this.c == selectedTermRequest.c && this.d == selectedTermRequest.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SelectedTermRequest(termId=");
        sb.append(this.a);
        sb.append(", setId=");
        sb.append(this.b);
        sb.append(", personId=");
        sb.append(this.c);
        sb.append(", source=");
        return android.support.v4.media.session.a.r(sb, this.d, ")");
    }
}
