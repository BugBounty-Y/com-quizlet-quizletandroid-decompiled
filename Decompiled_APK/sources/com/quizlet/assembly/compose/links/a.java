package com.quizlet.assembly.compose.links;

import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements c {
    public final String a;
    public final C0861v b;

    public a(String str, C0861v c0861v) {
        com.quizlet.features.infra.folder.create.coursefolder.composable.j painter = com.quizlet.features.infra.folder.create.coursefolder.composable.j.a;
        Intrinsics.checkNotNullParameter(painter, "painter");
        this.a = str;
        this.b = c0861v;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        aVar.getClass();
        Object obj2 = com.quizlet.features.infra.folder.create.coursefolder.composable.j.a;
        return obj2.equals(obj2) && Intrinsics.b(this.a, aVar.a) && this.b.equals(aVar.b);
    }

    public final int hashCode() {
        int iHashCode = com.quizlet.features.infra.folder.create.coursefolder.composable.j.a.hashCode() * 31;
        String str = this.a;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        C0861v c0861v = this.b;
        C c = D.b;
        return Long.hashCode(c0861v.a) + iHashCode2;
    }

    public final String toString() {
        return "Leading(painter=" + com.quizlet.features.infra.folder.create.coursefolder.composable.j.a + ", contentDescription=" + this.a + ", tint=" + this.b + ")";
    }
}
