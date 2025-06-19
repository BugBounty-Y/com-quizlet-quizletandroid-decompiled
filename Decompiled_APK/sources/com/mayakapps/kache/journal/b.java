package com.mayakapps.kache.journal;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements h {
    public final String a;

    public b(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        this.a = key;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    @Override // com.mayakapps.kache.journal.h
    public final String getKey() {
        return this.a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return d0.r(new StringBuilder("Cancel(key="), this.a, ')');
    }
}
