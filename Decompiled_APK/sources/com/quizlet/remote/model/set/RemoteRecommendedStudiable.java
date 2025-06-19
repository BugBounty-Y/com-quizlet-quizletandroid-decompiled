package com.quizlet.remote.model.set;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteRecommendedStudiable {
    public final Long a;
    public final int b;
    public final int c;
    public final int d;

    public RemoteRecommendedStudiable(Long l, int i, int i2, int i3) {
        this.a = l;
        this.b = i;
        this.c = i2;
        this.d = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteRecommendedStudiable)) {
            return false;
        }
        RemoteRecommendedStudiable remoteRecommendedStudiable = (RemoteRecommendedStudiable) obj;
        return Intrinsics.b(this.a, remoteRecommendedStudiable.a) && this.b == remoteRecommendedStudiable.b && this.c == remoteRecommendedStudiable.c && this.d == remoteRecommendedStudiable.d;
    }

    public final int hashCode() {
        Long l = this.a;
        return Integer.hashCode(this.d) + d0.b(this.c, d0.b(this.b, (l == null ? 0 : l.hashCode()) * 31, 31), 31);
    }

    public final String toString() {
        return "RemoteRecommendedStudiable(id=" + this.a + ", rank=" + this.b + ", studiableId=" + this.c + ", studiableType=" + this.d + ")";
    }
}
