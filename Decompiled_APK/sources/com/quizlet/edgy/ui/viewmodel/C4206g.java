package com.quizlet.edgy.ui.viewmodel;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.edgy.ui.viewmodel.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4206g extends s {
    public final com.quizlet.edgy.ui.recyclerview.adapter.i a;
    public final ArrayList b;
    public final r c;

    public C4206g(com.quizlet.edgy.ui.recyclerview.adapter.i searchSchoolItem, ArrayList searchSchoolItemList) {
        Intrinsics.checkNotNullParameter(searchSchoolItem, "searchSchoolItem");
        Intrinsics.checkNotNullParameter(searchSchoolItemList, "searchSchoolItemList");
        this.a = searchSchoolItem;
        this.b = searchSchoolItemList;
        this.c = new r(true, false, false, true, false, EnumC4212m.g, false, true, false, false, false, true);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4206g)) {
            return false;
        }
        C4206g c4206g = (C4206g) obj;
        return Intrinsics.b(this.a, c4206g.a) && Intrinsics.b(this.b, c4206g.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CourseSelected(searchSchoolItem=");
        sb.append(this.a);
        sb.append(", searchSchoolItemList=");
        return AbstractC0147y.f(")", sb, this.b);
    }
}
