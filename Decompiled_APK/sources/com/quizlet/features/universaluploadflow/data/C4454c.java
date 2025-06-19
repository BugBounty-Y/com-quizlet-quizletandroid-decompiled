package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.universaluploadflow.data.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4454c implements InterfaceC4456e {
    public final Function0 a;

    public C4454c(Function0 onCtaButtonClicked) {
        Intrinsics.checkNotNullParameter(onCtaButtonClicked, "onCtaButtonClicked");
        this.a = onCtaButtonClicked;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4454c) && Intrinsics.b(this.a, ((C4454c) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "NoInternet(onCtaButtonClicked=" + this.a + ")";
    }
}
