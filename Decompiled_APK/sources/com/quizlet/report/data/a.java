package com.quizlet.report.data;

import com.quizlet.generated.enums.Q0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final Q0 a;
    public final n b;
    public final boolean c;

    public a(Q0 q0, int i) {
        j jVar = j.a;
        q0 = (i & 1) != 0 ? null : q0;
        jVar = (i & 2) != 0 ? null : jVar;
        this.a = q0;
        this.b = jVar;
        this.c = jVar != null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        Q0 q0 = this.a;
        int iHashCode = (q0 == null ? 0 : q0.hashCode()) * 31;
        n nVar = this.b;
        return iHashCode + (nVar != null ? nVar.hashCode() : 0);
    }

    public final String toString() {
        return "Option(reason=" + this.a + ", next=" + this.b + ")";
    }
}
