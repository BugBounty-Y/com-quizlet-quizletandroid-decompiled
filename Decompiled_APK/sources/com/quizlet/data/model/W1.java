package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.J6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class W1 extends J6 {
    public final U1 b;

    public W1(U1 u1) {
        this.b = u1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof W1) && Intrinsics.b(this.b, ((W1) obj).b);
    }

    public final int hashCode() {
        U1 u1 = this.b;
        if (u1 == null) {
            return 0;
        }
        return u1.hashCode();
    }

    public final String toString() {
        return "Valid(data=" + this.b + ")";
    }
}
