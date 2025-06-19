package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.universaluploadflow.data.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4462k implements r {
    public final u a;

    public C4462k(u link) {
        Intrinsics.checkNotNullParameter(link, "link");
        this.a = link;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4462k) && Intrinsics.b(this.a, ((C4462k) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "LinkClicked(link=" + this.a + ")";
    }
}
