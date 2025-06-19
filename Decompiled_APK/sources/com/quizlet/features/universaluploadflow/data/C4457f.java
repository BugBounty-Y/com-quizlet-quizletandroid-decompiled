package com.quizlet.features.universaluploadflow.data;

import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.universaluploadflow.data.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4457f {
    public final boolean a;
    public final m2 b;

    public C4457f(boolean z, m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = z;
        this.b = source;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4457f)) {
            return false;
        }
        C4457f c4457f = (C4457f) obj;
        return this.a == c4457f.a && this.b == c4457f.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "FlashcardsNavigationData(isPublic=" + this.a + ", source=" + this.b + ")";
    }
}
