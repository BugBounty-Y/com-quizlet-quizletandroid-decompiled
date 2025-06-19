package com.quizlet.shared.cache;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final j a;
    public final t b;

    public b(j inMemoryCacheConfiguration, t persistentCacheConfiguration) {
        Intrinsics.checkNotNullParameter(inMemoryCacheConfiguration, "inMemoryCacheConfiguration");
        Intrinsics.checkNotNullParameter(persistentCacheConfiguration, "persistentCacheConfiguration");
        this.a = inMemoryCacheConfiguration;
        this.b = persistentCacheConfiguration;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a.a) * 31);
    }

    public final String toString() {
        return "CacheConfigurations(inMemoryCacheConfiguration=" + this.a + ", persistentCacheConfiguration=" + this.b + ")";
    }
}
