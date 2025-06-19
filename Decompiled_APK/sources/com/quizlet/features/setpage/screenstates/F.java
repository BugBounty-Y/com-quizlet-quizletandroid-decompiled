package com.quizlet.features.setpage.screenstates;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class F {
    public final boolean a;
    public final boolean b;
    public final String c;

    public F(String studyMaterialId, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        this.a = z;
        this.b = z2;
        this.c = studyMaterialId;
    }

    public static F a(F f, boolean z, String studyMaterialId, int i) {
        boolean z2 = (i & 1) != 0 ? f.a : true;
        if ((i & 2) != 0) {
            z = f.b;
        }
        if ((i & 4) != 0) {
            studyMaterialId = f.c;
        }
        f.getClass();
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        return new F(studyMaterialId, z2, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof F)) {
            return false;
        }
        F f = (F) obj;
        return this.a == f.a && this.b == f.b && Intrinsics.b(this.c, f.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SetPageToolbarState(shouldShowMoreMenu=");
        sb.append(this.a);
        sb.append(", shouldShowAddToFolderMenu=");
        sb.append(this.b);
        sb.append(", studyMaterialId=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
