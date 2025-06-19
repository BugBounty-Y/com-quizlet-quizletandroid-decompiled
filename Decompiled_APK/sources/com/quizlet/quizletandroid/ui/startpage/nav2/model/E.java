package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E extends AbstractC4707c {
    public final ArrayList d;

    public E(ArrayList data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof E) && this.d.equals(((E) obj).d);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "study_set_horizontal_home_data";
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("HorizontalStudySetHomeData(data="), this.d);
    }
}
