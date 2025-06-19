package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.d1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4120d1 {
    public final EnumC4130g1 a;

    public C4120d1(EnumC4130g1 progressType) {
        Intrinsics.checkNotNullParameter(progressType, "progressType");
        this.a = progressType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C4120d1) {
            return this.a == ((C4120d1) obj).a && Float.compare(0.2f, 0.2f) == 0 && Float.compare(1.0f, 1.0f) == 0;
        }
        return false;
    }

    public final int hashCode() {
        return Float.hashCode(1.0f) + android.support.v4.media.session.a.b(this.a.hashCode() * 31, 0.2f, 31);
    }

    public final String toString() {
        return "ProgressBarData(progressType=" + this.a + ", numerator=0.2, denominator=1.0)";
    }
}
