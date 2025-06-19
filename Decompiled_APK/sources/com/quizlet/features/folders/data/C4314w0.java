package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.w0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4314w0 implements InterfaceC4318y0 {
    public final z0 a;
    public final kotlinx.collections.immutable.b b;

    public C4314w0(z0 recommendationsType, kotlinx.collections.immutable.b recommendations) {
        Intrinsics.checkNotNullParameter(recommendationsType, "recommendationsType");
        Intrinsics.checkNotNullParameter(recommendations, "recommendations");
        this.a = recommendationsType;
        this.b = recommendations;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4314w0)) {
            return false;
        }
        C4314w0 c4314w0 = (C4314w0) obj;
        return this.a == c4314w0.a && Intrinsics.b(this.b, c4314w0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Content(recommendationsType=" + this.a + ", recommendations=" + this.b + ")";
    }
}
