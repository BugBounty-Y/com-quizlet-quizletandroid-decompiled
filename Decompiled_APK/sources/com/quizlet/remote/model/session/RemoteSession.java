package com.quizlet.remote.model.session;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSession {
    public final long a;
    public final long b;
    public final long c;
    public final int d;
    public final long e;
    public final Long f;
    public final int g;
    public final Long h;
    public final Boolean i;
    public final Boolean j;
    public final Long k;

    public RemoteSession(long j, long j2, long j3, int i, long j4, Long l, int i2, Long l2, Boolean bool, Boolean bool2, Long l3) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = i;
        this.e = j4;
        this.f = l;
        this.g = i2;
        this.h = l2;
        this.i = bool;
        this.j = bool2;
        this.k = l3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSession)) {
            return false;
        }
        RemoteSession remoteSession = (RemoteSession) obj;
        return this.a == remoteSession.a && this.b == remoteSession.b && this.c == remoteSession.c && this.d == remoteSession.d && this.e == remoteSession.e && Intrinsics.b(this.f, remoteSession.f) && this.g == remoteSession.g && Intrinsics.b(this.h, remoteSession.h) && Intrinsics.b(this.i, remoteSession.i) && Intrinsics.b(this.j, remoteSession.j) && Intrinsics.b(this.k, remoteSession.k);
    }

    public final int hashCode() {
        int iD = d0.d(d0.b(this.d, d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31), 31, this.e);
        Long l = this.f;
        int iB = d0.b(this.g, (iD + (l == null ? 0 : l.hashCode())) * 31, 31);
        Long l2 = this.h;
        int iHashCode = (iB + (l2 == null ? 0 : l2.hashCode())) * 31;
        Boolean bool = this.i;
        int iHashCode2 = (iHashCode + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.j;
        int iHashCode3 = (iHashCode2 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Long l3 = this.k;
        return iHashCode3 + (l3 != null ? l3.hashCode() : 0);
    }

    public final String toString() {
        return "RemoteSession(id=" + this.a + ", personId=" + this.b + ", itemId=" + this.c + ", itemType=" + this.d + ", timestamp=" + this.e + ", endedTimestamp=" + this.f + ", type=" + this.g + ", score=" + this.h + ", hidden=" + this.i + ", selectedOnly=" + this.j + ", lastModified=" + this.k + ")";
    }
}
