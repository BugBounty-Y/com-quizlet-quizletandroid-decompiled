package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A0 implements C0 {
    public final com.quizlet.features.infra.folder.menu.data.x a;

    public A0(com.quizlet.features.infra.folder.menu.data.x event) {
        Intrinsics.checkNotNullParameter(event, "event");
        this.a = event;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof A0) && Intrinsics.b(this.a, ((A0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "AddToFolder(event=" + this.a + ")";
    }
}
