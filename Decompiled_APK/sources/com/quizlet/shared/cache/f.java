package com.quizlet.shared.cache;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final serialization.e a;

    public f(serialization.e key) {
        Intrinsics.checkNotNullParameter(key, "key");
        this.a = key;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof f) {
            return Intrinsics.b(this.a, ((f) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Boolean.hashCode(false) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ExpirableCacheKey(key=" + this.a + ", returnIfStale=false)";
    }
}
