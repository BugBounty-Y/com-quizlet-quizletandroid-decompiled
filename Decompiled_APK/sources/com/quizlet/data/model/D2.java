package com.quizlet.data.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class D2 implements x2 {
    public final C2 a;
    public final ArrayList b;

    public D2(C2 streakData, ArrayList sets) {
        Intrinsics.checkNotNullParameter(streakData, "streakData");
        Intrinsics.checkNotNullParameter(sets, "sets");
        this.a = streakData;
        this.b = sets;
    }

    @Override // com.quizlet.data.model.x2
    public final boolean a() {
        return true;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D2)) {
            return false;
        }
        D2 d2 = (D2) obj;
        return this.a.equals(d2.a) && this.b.equals(d2.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("WidgetSuggestedSets(streakData=");
        sb.append(this.a);
        sb.append(", sets=");
        return AbstractC0147y.f(")", sb, this.b);
    }
}
