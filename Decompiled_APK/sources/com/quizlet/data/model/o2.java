package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o2 implements InterfaceC4176w0 {
    public final com.quizlet.generated.enums.P a;
    public final Long b;
    public final long c;
    public final com.quizlet.generated.enums.S d;

    public o2(com.quizlet.generated.enums.P eventType, Long l, long j, com.quizlet.generated.enums.S reason) {
        Intrinsics.checkNotNullParameter(eventType, "eventType");
        Intrinsics.checkNotNullParameter(reason, "reason");
        this.a = eventType;
        this.b = l;
        this.c = j;
        this.d = reason;
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final com.quizlet.generated.enums.S B() {
        return this.d;
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final boolean a0() {
        return false;
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final com.quizlet.generated.enums.P c0() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o2)) {
            return false;
        }
        o2 o2Var = (o2) obj;
        return this.a == o2Var.a && Intrinsics.b(this.b, o2Var.b) && this.c == o2Var.c && this.d == o2Var.d;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Long l = this.b;
        return this.d.hashCode() + androidx.compose.animation.d0.d((iHashCode + (l == null ? 0 : l.hashCode())) * 31, 31, this.c);
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final long i() {
        return this.c;
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final Long r() {
        return this.b;
    }

    public final String toString() {
        return "Unmetered(eventType=" + this.a + ", resourceId=" + this.b + ", userId=" + this.c + ", reason=" + this.d + ")";
    }
}
