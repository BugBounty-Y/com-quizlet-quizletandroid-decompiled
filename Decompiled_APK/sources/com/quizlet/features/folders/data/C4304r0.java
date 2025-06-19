package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.r0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4304r0 implements InterfaceC4312v0 {
    public final String a;

    public C4304r0(String isbn) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        this.a = isbn;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4304r0) && Intrinsics.b(this.a, ((C4304r0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("GoToTextbook(isbn="), this.a, ")");
    }
}
