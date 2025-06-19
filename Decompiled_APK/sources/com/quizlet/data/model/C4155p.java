package com.quizlet.data.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4155p extends AbstractC4163s {
    public final ArrayList a;

    public C4155p(ArrayList dates) {
        Intrinsics.checkNotNullParameter(dates, "dates");
        this.a = dates;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4155p) && this.a.equals(((C4155p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("AchievementsHistory(dates="), this.a);
    }
}
