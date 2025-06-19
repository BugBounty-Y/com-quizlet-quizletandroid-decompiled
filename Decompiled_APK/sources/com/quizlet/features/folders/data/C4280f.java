package com.quizlet.features.folders.data;

/* renamed from: com.quizlet.features.folders.data.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4280f implements InterfaceC4315x {
    public final long a;

    public C4280f(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4280f) && this.a == ((C4280f) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("CreatorClicked(userId="));
    }
}
