package com.quizlet.features.notes.common.events;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements y {
    public final com.quizlet.features.notes.detail.menu.f a;

    public o(com.quizlet.features.notes.detail.menu.f menuOptions) {
        Intrinsics.checkNotNullParameter(menuOptions, "menuOptions");
        this.a = menuOptions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof o) && Intrinsics.b(this.a, ((o) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "MenuItemClicked(menuOptions=" + this.a + ")";
    }
}
