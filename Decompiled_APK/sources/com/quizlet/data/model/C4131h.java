package com.quizlet.data.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4131h extends AbstractC4140k {
    public final ArrayList a;

    public C4131h(ArrayList badges) {
        Intrinsics.checkNotNullParameter(badges, "badges");
        this.a = badges;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4131h) && this.a.equals(((C4131h) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("AchievementBadges(badges="), this.a);
    }
}
