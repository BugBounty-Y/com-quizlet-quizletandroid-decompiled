package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4309u implements InterfaceC4307t {
    public final com.quizlet.features.folders.menu.i a;

    public C4309u(com.quizlet.features.folders.menu.i menuOptions) {
        Intrinsics.checkNotNullParameter(menuOptions, "menuOptions");
        this.a = menuOptions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4309u) && Intrinsics.b(this.a, ((C4309u) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "FolderMenuItemClicked(menuOptions=" + this.a + ")";
    }
}
