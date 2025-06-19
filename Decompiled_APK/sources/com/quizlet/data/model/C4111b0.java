package com.quizlet.data.model;

import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.b0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4111b0 {
    public final String a;
    public final String b;
    public final byte[] c;

    public C4111b0(byte[] byteArray, String fileName, String mimeType) {
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        Intrinsics.checkNotNullParameter(mimeType, "mimeType");
        Intrinsics.checkNotNullParameter(byteArray, "byteArray");
        this.a = fileName;
        this.b = mimeType;
        this.c = byteArray;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4111b0)) {
            return false;
        }
        C4111b0 c4111b0 = (C4111b0) obj;
        return Intrinsics.b(this.a, c4111b0.a) && Intrinsics.b(this.b, c4111b0.b) && Intrinsics.b(this.c, c4111b0.c);
    }

    public final int hashCode() {
        return Arrays.hashCode(this.c) + androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        String string = Arrays.toString(this.c);
        StringBuilder sb = new StringBuilder("FileUpload(fileName=");
        sb.append(this.a);
        sb.append(", mimeType=");
        return androidx.compose.ui.node.B.j(sb, this.b, ", byteArray=", string, ")");
    }
}
