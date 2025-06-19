package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.match.data.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4366w extends AbstractC4367x {
    public final EnumC4369z a;

    public C4366w(EnumC4369z gameType) {
        Intrinsics.checkNotNullParameter(gameType, "gameType");
        this.a = gameType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4366w) && this.a == ((C4366w) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Ready(gameType=" + this.a + ")";
    }
}
