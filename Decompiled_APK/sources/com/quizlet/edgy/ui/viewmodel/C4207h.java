package com.quizlet.edgy.ui.viewmodel;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.edgy.ui.viewmodel.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4207h extends s {
    public final com.quizlet.edgy.ui.recyclerview.adapter.i a;
    public final List b;
    public final r c;

    public C4207h(com.quizlet.edgy.ui.recyclerview.adapter.i searchSchoolItem, List searchCourseItemList) {
        Intrinsics.checkNotNullParameter(searchSchoolItem, "searchSchoolItem");
        Intrinsics.checkNotNullParameter(searchCourseItemList, "searchCourseItemList");
        this.a = searchSchoolItem;
        this.b = searchCourseItemList;
        this.c = new r(true, false, false, true, false, EnumC4212m.f, false, false, false, false, true, false);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4207h)) {
            return false;
        }
        C4207h c4207h = (C4207h) obj;
        return Intrinsics.b(this.a, c4207h.a) && Intrinsics.b(this.b, c4207h.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "CourseSuccess(searchSchoolItem=" + this.a + ", searchCourseItemList=" + this.b + ")";
    }
}
