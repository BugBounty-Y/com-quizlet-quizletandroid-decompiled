package com.quizlet.quizletandroid.ui.library.data;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3690o5;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.data.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4653g extends AbstractC3690o5 {
    public final kotlinx.collections.immutable.e a;

    public C4653g(kotlinx.collections.immutable.e list) {
        Intrinsics.checkNotNullParameter(list, "list");
        this.a = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4653g) && Intrinsics.b(this.a, ((C4653g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Content(list=" + this.a + ")";
    }
}
