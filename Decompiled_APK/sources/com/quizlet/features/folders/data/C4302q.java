package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4302q implements InterfaceC4296n {
    public final com.quizlet.features.folders.menu.q a;

    public C4302q(com.quizlet.features.folders.menu.q menuOptions) {
        Intrinsics.checkNotNullParameter(menuOptions, "menuOptions");
        this.a = menuOptions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4302q) && Intrinsics.b(this.a, ((C4302q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "FolderMaterialsMenuItemClicked(menuOptions=" + this.a + ")";
    }
}
