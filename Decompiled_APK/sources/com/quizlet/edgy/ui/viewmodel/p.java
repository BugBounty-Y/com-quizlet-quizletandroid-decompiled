package com.quizlet.edgy.ui.viewmodel;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class p extends s {
    public final ArrayList a;
    public final r b;

    public p(ArrayList searchSchoolItemList) {
        Intrinsics.checkNotNullParameter(searchSchoolItemList, "searchSchoolItemList");
        this.a = searchSchoolItemList;
        this.b = new r(true, false, true, false, false, EnumC4212m.e, false, true, false, false, true, false);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof p) && this.a.equals(((p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("SchoolsSuccess(searchSchoolItemList="), this.a);
    }
}
