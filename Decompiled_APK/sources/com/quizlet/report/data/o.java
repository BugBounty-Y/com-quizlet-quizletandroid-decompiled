package com.quizlet.report.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o {
    public final n a;
    public final Integer b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final d g;

    public o(n option, Integer num, boolean z, boolean z2, boolean z3, boolean z4, d dVar) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
        this.b = num;
        this.c = z;
        this.d = z2;
        this.e = z3;
        this.f = z4;
        this.g = dVar;
    }

    public static o a(o oVar, n nVar, Integer num, boolean z, boolean z2, boolean z3, d dVar, int i) {
        if ((i & 1) != 0) {
            nVar = oVar.a;
        }
        n option = nVar;
        if ((i & 2) != 0) {
            num = oVar.b;
        }
        Integer num2 = num;
        boolean z4 = oVar.c;
        if ((i & 8) != 0) {
            z = oVar.d;
        }
        boolean z5 = z;
        if ((i & 16) != 0) {
            z2 = oVar.e;
        }
        boolean z6 = z2;
        if ((i & 32) != 0) {
            z3 = oVar.f;
        }
        boolean z7 = z3;
        if ((i & 64) != 0) {
            dVar = oVar.g;
        }
        oVar.getClass();
        Intrinsics.checkNotNullParameter(option, "option");
        return new o(option, num2, z4, z5, z6, z7, dVar);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.a, oVar.a) && Intrinsics.b(this.b, oVar.b) && this.c == oVar.c && this.d == oVar.d && this.e == oVar.e && this.f == oVar.f && Intrinsics.b(this.g, oVar.g);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Integer num = this.b;
        int iG = d0.g(d0.g(d0.g(d0.g((iHashCode + (num == null ? 0 : num.hashCode())) * 31, 31, this.c), 31, this.d), 31, this.e), 31, this.f);
        d dVar = this.g;
        return iG + (dVar != null ? dVar.hashCode() : 0);
    }

    public final String toString() {
        return "ReportUiState(option=" + this.a + ", selectedIndex=" + this.b + ", isAiProduct=" + this.c + ", isSubmitting=" + this.d + ", hasSecondaryButton=" + this.e + ", isReportComplete=" + this.f + ", error=" + this.g + ")";
    }
}
