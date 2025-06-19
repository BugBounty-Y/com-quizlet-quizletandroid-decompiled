package com.quizlet.viewmodel.state;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends c {
    public final Object a;

    public b(Object obj) {
        this.a = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        Object obj = this.a;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("RenderScreen(renderState="), this.a, ")");
    }
}
