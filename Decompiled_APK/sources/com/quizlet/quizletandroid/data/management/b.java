package com.quizlet.quizletandroid.data.management;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final io.reactivex.rxjava3.subjects.b a;
    public final com.quizlet.infra.legacysyncengine.datasources.f b;

    public b(io.reactivex.rxjava3.subjects.b subject, com.quizlet.infra.legacysyncengine.datasources.f listener) {
        Intrinsics.checkNotNullParameter(subject, "subject");
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.a = subject;
        this.b = listener;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a.equals(bVar.a) && this.b.equals(bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "RequestTracker(subject=" + this.a + ", listener=" + this.b + ")";
    }
}
