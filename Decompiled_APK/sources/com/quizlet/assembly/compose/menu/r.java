package com.quizlet.assembly.compose.menu;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class r {
    public final t a;

    public r(t tabletProperties) {
        Intrinsics.checkNotNullParameter(tabletProperties, "tabletProperties");
        this.a = tabletProperties;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof r) && Intrinsics.b(this.a, ((r) obj).a);
    }

    public final int hashCode() {
        return Long.hashCode(this.a.a);
    }

    public final String toString() {
        return "AssemblyMenuProperties(tabletProperties=" + this.a + ")";
    }
}
