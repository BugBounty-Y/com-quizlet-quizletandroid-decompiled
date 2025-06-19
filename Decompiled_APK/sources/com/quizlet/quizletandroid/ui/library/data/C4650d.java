package com.quizlet.quizletandroid.ui.library.data;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3674m5;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4650d extends AbstractC3674m5 {
    public final kotlinx.collections.immutable.e a;

    public C4650d(kotlinx.collections.immutable.e list) {
        Intrinsics.checkNotNullParameter(list, "list");
        this.a = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4650d) && Intrinsics.b(this.a, ((C4650d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Content(list=" + this.a + ")";
    }
}
