package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class V extends AbstractC4368y {
    public final boolean a;
    public final String b;

    public V(boolean z, String gameTag) {
        Intrinsics.checkNotNullParameter(gameTag, "gameTag");
        this.a = z;
        this.b = gameTag;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof V)) {
            return false;
        }
        V v = (V) obj;
        return this.a == v.a && Intrinsics.b(this.b, v.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "PlayGame(playWithSelected=" + this.a + ", gameTag=" + this.b + ")";
    }
}
