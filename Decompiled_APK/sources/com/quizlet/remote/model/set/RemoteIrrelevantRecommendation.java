package com.quizlet.remote.model.set;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteIrrelevantRecommendation {
    public final Long a;
    public final long b;
    public final long c;
    public final int d;
    public final Long e;

    public RemoteIrrelevantRecommendation(Long l, long j, long j2, int i, Long l2) {
        this.a = l;
        this.b = j;
        this.c = j2;
        this.d = i;
        this.e = l2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteIrrelevantRecommendation)) {
            return false;
        }
        RemoteIrrelevantRecommendation remoteIrrelevantRecommendation = (RemoteIrrelevantRecommendation) obj;
        return Intrinsics.b(this.a, remoteIrrelevantRecommendation.a) && this.b == remoteIrrelevantRecommendation.b && this.c == remoteIrrelevantRecommendation.c && this.d == remoteIrrelevantRecommendation.d && Intrinsics.b(this.e, remoteIrrelevantRecommendation.e);
    }

    public final int hashCode() {
        Long l = this.a;
        int iB = d0.b(this.d, d0.d(d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b), 31, this.c), 31);
        Long l2 = this.e;
        return iB + (l2 != null ? l2.hashCode() : 0);
    }

    public final String toString() {
        return "RemoteIrrelevantRecommendation(id=" + this.a + ", personId=" + this.b + ", modelId=" + this.c + ", modelType=" + this.d + ", created=" + this.e + ")";
    }
}
