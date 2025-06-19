package com.quizlet.features.folders.menu;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements u {
    public final Object a;
    public final String b;
    public final y1 c;

    public t(List items, String studyMaterialId, y1 y1Var) {
        Intrinsics.checkNotNullParameter(items, "items");
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        this.a = items;
        this.b = studyMaterialId;
        this.c = y1Var;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        t tVar = (t) obj;
        return Intrinsics.b(this.a, tVar.a) && Intrinsics.b(this.b, tVar.b) && this.c == tVar.c;
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        y1 y1Var = this.c;
        return iE + (y1Var == null ? 0 : y1Var.hashCode());
    }

    public final String toString() {
        return "Open(items=" + this.a + ", studyMaterialId=" + this.b + ", studyMaterialType=" + this.c + ")";
    }
}
