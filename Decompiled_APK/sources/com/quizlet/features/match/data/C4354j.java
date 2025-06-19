package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.match.data.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4354j extends O {
    public final H a;

    public C4354j(H matchInfoForSharing) {
        Intrinsics.checkNotNullParameter(matchInfoForSharing, "matchInfoForSharing");
        this.a = matchInfoForSharing;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4354j) && Intrinsics.b(this.a, ((C4354j) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "MatchCanShareData(matchInfoForSharing=" + this.a + ")";
    }
}
