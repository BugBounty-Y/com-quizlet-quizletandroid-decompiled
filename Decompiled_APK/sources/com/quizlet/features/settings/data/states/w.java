package com.quizlet.features.settings.data.states;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w implements x {
    public final String a;
    public final com.quizlet.features.settings.data.models.b b;

    public w(String reAuthToken, com.quizlet.features.settings.data.models.b bVar) {
        Intrinsics.checkNotNullParameter(reAuthToken, "reAuthToken");
        this.a = reAuthToken;
        this.b = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w)) {
            return false;
        }
        w wVar = (w) obj;
        return Intrinsics.b(this.a, wVar.a) && this.b == wVar.b;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        com.quizlet.features.settings.data.models.b bVar = this.b;
        return iHashCode + (bVar == null ? 0 : bVar.hashCode());
    }

    public final String toString() {
        return "Success(reAuthToken=" + this.a + ", requestType=" + this.b + ")";
    }
}
