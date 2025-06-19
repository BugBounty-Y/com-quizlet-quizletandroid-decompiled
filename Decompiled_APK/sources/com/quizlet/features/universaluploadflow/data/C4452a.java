package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.universaluploadflow.data.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4452a implements InterfaceC4456e {
    public final int a;
    public final com.quizlet.features.universaluploadflow.viewmodel.c b;

    public C4452a(int i, com.quizlet.features.universaluploadflow.viewmodel.c onCtaButtonClicked) {
        Intrinsics.checkNotNullParameter(onCtaButtonClicked, "onCtaButtonClicked");
        this.a = i;
        this.b = onCtaButtonClicked;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4452a)) {
            return false;
        }
        C4452a c4452a = (C4452a) obj;
        return this.a == c4452a.a && this.b.equals(c4452a.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "FileTooLarge(fileSize=" + this.a + ", onCtaButtonClicked=" + this.b + ")";
    }
}
