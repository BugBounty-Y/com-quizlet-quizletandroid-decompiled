package com.quizlet.shared.models.api.notes;

import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import java.util.Arrays;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final String a;
    public final String b;
    public final byte[] c;

    public c(byte[] byteArray, String fileName, String mimeType) {
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
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        return Arrays.hashCode(this.c) + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        String string = Arrays.toString(this.c);
        StringBuilder sb = new StringBuilder("FileUpload(fileName=");
        sb.append(this.a);
        sb.append(", mimeType=");
        return B.j(sb, this.b, ", byteArray=", string, ")");
    }
}
