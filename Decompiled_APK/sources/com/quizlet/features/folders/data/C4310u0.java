package com.quizlet.features.folders.data;

/* renamed from: com.quizlet.features.folders.data.u0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4310u0 implements InterfaceC4312v0 {
    public final long a;

    public C4310u0(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4310u0) && this.a == ((C4310u0) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("GoToUser(userId="));
    }
}
