package com.quizlet.features.folders.addtofolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements n {
    public final t a;

    public m(t selectedTab) {
        Intrinsics.checkNotNullParameter(selectedTab, "selectedTab");
        this.a = selectedTab;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && this.a == ((m) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "TabClicked(selectedTab=" + this.a + ")";
    }
}
