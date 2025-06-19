package com.quizlet.features.universaluploadflow.pastetext.data;

import com.quizlet.features.universaluploadflow.data.InterfaceC4456e;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n implements p {
    public final InterfaceC4456e a;

    public n(InterfaceC4456e reason) {
        Intrinsics.checkNotNullParameter(reason, "reason");
        this.a = reason;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(reason=" + this.a + ")";
    }
}
