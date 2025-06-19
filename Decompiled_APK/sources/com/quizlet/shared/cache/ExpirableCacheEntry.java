package com.quizlet.shared.cache;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class ExpirableCacheEntry extends serialization.e {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e = {serialization.e.Companion.serializer(), null, null};
    public final serialization.e b;
    public final long c;
    public final Boolean d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ExpirableCacheEntry$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ExpirableCacheEntry(int i, serialization.e eVar, long j, Boolean bool) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, ExpirableCacheEntry$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = eVar;
        this.c = j;
        this.d = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExpirableCacheEntry)) {
            return false;
        }
        ExpirableCacheEntry expirableCacheEntry = (ExpirableCacheEntry) obj;
        return Intrinsics.b(this.b, expirableCacheEntry.b) && this.c == expirableCacheEntry.c && Intrinsics.b(this.d, expirableCacheEntry.d);
    }

    public final int hashCode() {
        int iD = d0.d(this.b.hashCode() * 31, 31, this.c);
        Boolean bool = this.d;
        return iD + (bool == null ? 0 : bool.hashCode());
    }

    public final String toString() {
        return "ExpirableCacheEntry(entry=" + this.b + ", expiresAt=" + this.c + ", isStale=" + this.d + ")";
    }
}
