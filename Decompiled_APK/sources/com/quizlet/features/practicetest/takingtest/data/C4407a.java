package com.quizlet.features.practicetest.takingtest.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.practicetest.takingtest.data.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4407a {
    public final String a;
    public final ArrayList b;

    public C4407a(ArrayList arrayList, String option) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
        this.b = arrayList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4407a)) {
            return false;
        }
        C4407a c4407a = (C4407a) obj;
        return Intrinsics.b(this.a, c4407a.a) && Intrinsics.b(this.b, c4407a.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        ArrayList arrayList = this.b;
        return iHashCode + (arrayList == null ? 0 : arrayList.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MultipleChoiceOption(option=");
        sb.append(this.a);
        sb.append(", images=");
        return AbstractC0147y.f(")", sb, this.b);
    }
}
