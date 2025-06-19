package com.quizlet.features.universaluploadflow.data;

import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.universaluploadflow.data.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4455d implements InterfaceC4456e {
    public final m2 a;

    public C4455d(m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4455d) && this.a == ((C4455d) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "UserIneligible(source=" + this.a + ")";
    }
}
