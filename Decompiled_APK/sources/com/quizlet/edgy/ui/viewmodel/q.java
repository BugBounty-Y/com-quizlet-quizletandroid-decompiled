package com.quizlet.edgy.ui.viewmodel;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class q extends s {
    public final ArrayList a;
    public final r b;

    public q(ArrayList arrayList) {
        this.a = arrayList;
        if (arrayList == null || arrayList.isEmpty()) {
            EnumC4212m enumC4212m = EnumC4212m.a;
        } else {
            EnumC4212m enumC4212m2 = EnumC4212m.a;
        }
        this.b = new r(true, false, true, false, false, EnumC4212m.b, true, false, true, false, true, false);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && Intrinsics.b(this.a, ((q) obj).a);
    }

    public final int hashCode() {
        ArrayList arrayList = this.a;
        if (arrayList == null) {
            return 0;
        }
        return arrayList.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("SearchSchool(popularSchoolList="), this.a);
    }
}
