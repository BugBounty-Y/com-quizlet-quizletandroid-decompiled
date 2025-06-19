package com.quizlet.shared.cache;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t {
    public final String a;
    public final long b;

    public t(String path, long j) {
        Intrinsics.checkNotNullParameter(path, "path");
        this.a = path;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return Intrinsics.b(this.a, tVar.a) && this.b == tVar.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PersistentCacheConfiguration(path=");
        sb.append(this.a);
        sb.append(", maxSizeBytes=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}
