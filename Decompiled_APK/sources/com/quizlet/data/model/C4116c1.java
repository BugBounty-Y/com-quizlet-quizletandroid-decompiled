package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.c1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4116c1 extends I0 {
    public final Object a;

    public C4116c1(Object obj) {
        this.a = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4116c1) && Intrinsics.b(this.a, ((C4116c1) obj).a);
    }

    public final int hashCode() {
        Object obj = this.a;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("Present(value="), this.a, ")");
    }
}
