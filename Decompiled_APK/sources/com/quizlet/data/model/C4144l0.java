package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.l0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4144l0 extends A {
    public final String a;

    public C4144l0(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = name;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4144l0) && Intrinsics.b(this.a, ((C4144l0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("HeaderItem(name="), this.a, ")");
    }
}
