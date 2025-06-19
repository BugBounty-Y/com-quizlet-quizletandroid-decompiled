package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4290k implements T {
    public final com.quizlet.features.folders.menu.c a;

    public C4290k(com.quizlet.features.folders.menu.c menuOptions) {
        Intrinsics.checkNotNullParameter(menuOptions, "menuOptions");
        this.a = menuOptions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4290k) && Intrinsics.b(this.a, ((C4290k) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "FolderAddNewMenuItemClicked(menuOptions=" + this.a + ")";
    }
}
