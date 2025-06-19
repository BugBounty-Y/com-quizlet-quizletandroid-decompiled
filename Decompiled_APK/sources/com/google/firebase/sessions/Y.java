package com.google.firebase.sessions;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Y {
    public final String a;
    public final String b;
    public final int c;
    public final long d;
    public final C3989k e;
    public final String f;
    public final String g;

    public Y(String sessionId, String firstSessionId, int i, long j, C3989k dataCollectionStatus, String firebaseInstallationId, String firebaseAuthenticationToken) {
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        Intrinsics.checkNotNullParameter(firstSessionId, "firstSessionId");
        Intrinsics.checkNotNullParameter(dataCollectionStatus, "dataCollectionStatus");
        Intrinsics.checkNotNullParameter(firebaseInstallationId, "firebaseInstallationId");
        Intrinsics.checkNotNullParameter(firebaseAuthenticationToken, "firebaseAuthenticationToken");
        this.a = sessionId;
        this.b = firstSessionId;
        this.c = i;
        this.d = j;
        this.e = dataCollectionStatus;
        this.f = firebaseInstallationId;
        this.g = firebaseAuthenticationToken;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Y)) {
            return false;
        }
        Y y = (Y) obj;
        return Intrinsics.b(this.a, y.a) && Intrinsics.b(this.b, y.b) && this.c == y.c && this.d == y.d && Intrinsics.b(this.e, y.e) && Intrinsics.b(this.f, y.f) && Intrinsics.b(this.g, y.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + androidx.compose.animation.d0.e((this.e.hashCode() + androidx.compose.animation.d0.d(androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31), 31, this.d)) * 31, 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SessionInfo(sessionId=");
        sb.append(this.a);
        sb.append(", firstSessionId=");
        sb.append(this.b);
        sb.append(", sessionIndex=");
        sb.append(this.c);
        sb.append(", eventTimestampUs=");
        sb.append(this.d);
        sb.append(", dataCollectionStatus=");
        sb.append(this.e);
        sb.append(", firebaseInstallationId=");
        sb.append(this.f);
        sb.append(", firebaseAuthenticationToken=");
        return androidx.compose.animation.d0.r(sb, this.g, ')');
    }
}
