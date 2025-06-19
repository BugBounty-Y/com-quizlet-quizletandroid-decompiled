package com.mayakapps.kache.journal;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements h {
    public final String a;
    public final String b;

    public d(String key, String transformedKey) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(transformedKey, "transformedKey");
        this.a = key;
        this.b = transformedKey;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b);
    }

    @Override // com.mayakapps.kache.journal.h
    public final String getKey() {
        return this.a;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CleanWithTransformedKey(key=");
        sb.append(this.a);
        sb.append(", transformedKey=");
        return d0.r(sb, this.b, ')');
    }
}
