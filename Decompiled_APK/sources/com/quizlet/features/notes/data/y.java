package com.quizlet.features.notes.data;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.B;
import kotlin.C;
import kotlin.D;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y {
    public final String a;
    public final long b;

    public y(String str, long j) {
        this.a = str;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return Intrinsics.b(this.a, yVar.a) && C0861v.c(this.b, yVar.b);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = str == null ? 0 : str.hashCode();
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.b) + (iHashCode * 31);
    }

    public final String toString() {
        return B.j(new StringBuilder("ScanNotesImageProcessedData(errorDescription="), this.a, ", errorColor=", C0861v.i(this.b), ")");
    }
}
