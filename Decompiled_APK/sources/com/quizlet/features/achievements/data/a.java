package com.quizlet.features.achievements.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements d {
    public final String a;

    public a(String badgeId) {
        Intrinsics.checkNotNullParameter(badgeId, "badgeId");
        this.a = badgeId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("BadgeClicked(badgeId="), this.a, ")");
    }
}
