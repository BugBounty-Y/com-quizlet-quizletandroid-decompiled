package com.quizlet.features.settings.composables;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j {
    public final Function0 a;
    public final Function1 b;

    public j(Function0 onOfflineUnavailableClick, Function1 onCheckedChanged) {
        Intrinsics.checkNotNullParameter(onOfflineUnavailableClick, "onOfflineUnavailableClick");
        Intrinsics.checkNotNullParameter(onCheckedChanged, "onCheckedChanged");
        this.a = onOfflineUnavailableClick;
        this.b = onCheckedChanged;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return Intrinsics.b(this.a, jVar.a) && Intrinsics.b(this.b, jVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "OfflineStudyingActions(onOfflineUnavailableClick=" + this.a + ", onCheckedChanged=" + this.b + ")";
    }
}
