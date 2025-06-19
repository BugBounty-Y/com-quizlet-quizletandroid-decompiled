package com.quizlet.features.infra.snackbar;

import androidx.compose.animation.d0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends a {
    public final k a;
    public final int b;
    public final com.quizlet.qutils.string.g c;
    public final com.quizlet.qutils.string.g d;
    public final Function0 e;

    public l(k snackbarType, int i, com.quizlet.qutils.string.g gVar, com.quizlet.qutils.string.f fVar, Function0 function0, int i2) {
        fVar = (i2 & 16) != 0 ? null : fVar;
        function0 = (i2 & 64) != 0 ? null : function0;
        Intrinsics.checkNotNullParameter(snackbarType, "snackbarType");
        this.a = snackbarType;
        this.b = i;
        this.c = gVar;
        this.d = fVar;
        this.e = function0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return this.a == lVar.a && this.b == lVar.b && this.c.equals(lVar.c) && Intrinsics.b(this.d, lVar.d) && Intrinsics.b(this.e, lVar.e);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + d0.b(this.b, this.a.hashCode() * 31, 31)) * 961;
        com.quizlet.qutils.string.g gVar = this.d;
        int iHashCode2 = (iHashCode + (gVar == null ? 0 : gVar.hashCode())) * 961;
        Function0 function0 = this.e;
        return iHashCode2 + (function0 != null ? function0.hashCode() : 0);
    }

    public final String toString() {
        return "ShowSnackbarData(snackbarType=" + this.a + ", length=" + this.b + ", msgData=" + this.c + ", msgString=null, actionData=" + this.d + ", actionString=null, actionListener=" + this.e + ")";
    }
}
