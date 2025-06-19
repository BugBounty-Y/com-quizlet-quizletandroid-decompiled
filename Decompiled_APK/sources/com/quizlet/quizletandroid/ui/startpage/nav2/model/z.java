package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z extends AbstractC4707c {
    public final ArrayList d;

    public z(ArrayList data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof z) && this.d.equals(((z) obj).d);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "group_horizontal";
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("HorizontalGroupHomeData(data="), this.d);
    }
}
