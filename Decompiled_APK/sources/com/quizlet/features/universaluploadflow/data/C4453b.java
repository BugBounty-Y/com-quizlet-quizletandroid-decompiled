package com.quizlet.features.universaluploadflow.data;

import com.quizlet.data.model.m2;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.universaluploadflow.data.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4453b implements InterfaceC4456e {
    public final m2 a;
    public final Function0 b;

    public C4453b(m2 source, Function0 onCtaButtonClicked) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(onCtaButtonClicked, "onCtaButtonClicked");
        this.a = source;
        this.b = onCtaButtonClicked;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4453b)) {
            return false;
        }
        C4453b c4453b = (C4453b) obj;
        return this.a == c4453b.a && Intrinsics.b(this.b, c4453b.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "GenericError(source=" + this.a + ", onCtaButtonClicked=" + this.b + ")";
    }
}
