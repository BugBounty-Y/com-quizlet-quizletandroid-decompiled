package com.quizlet.data.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.H6;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.x0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4179x0 implements InterfaceC4176w0 {
    public final int a;
    public final int b;
    public final com.quizlet.generated.enums.P c;
    public final Long d;
    public final long e;
    public final com.quizlet.generated.enums.S f;
    public final boolean g;

    public C4179x0(int i, int i2, com.quizlet.generated.enums.P eventType, Long l, long j, com.quizlet.generated.enums.S reason) {
        Intrinsics.checkNotNullParameter(eventType, "eventType");
        Intrinsics.checkNotNullParameter(reason, "reason");
        this.a = i;
        this.b = i2;
        this.c = eventType;
        this.d = l;
        this.e = j;
        this.f = reason;
        this.g = i >= H6.b(eventType) + i2;
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final com.quizlet.generated.enums.S B() {
        return this.f;
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final boolean a0() {
        return this.g;
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final com.quizlet.generated.enums.P c0() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4179x0)) {
            return false;
        }
        C4179x0 c4179x0 = (C4179x0) obj;
        return this.a == c4179x0.a && this.b == c4179x0.b && this.c == c4179x0.c && Intrinsics.b(this.d, c4179x0.d) && this.e == c4179x0.e && this.f == c4179x0.f;
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + androidx.compose.animation.d0.b(this.b, Integer.hashCode(this.a) * 31, 31)) * 31;
        Long l = this.d;
        return this.f.hashCode() + androidx.compose.animation.d0.d((iHashCode + (l == null ? 0 : l.hashCode())) * 31, 31, this.e);
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final long i() {
        return this.e;
    }

    @Override // com.quizlet.data.model.InterfaceC4176w0
    public final Long r() {
        return this.d;
    }

    public final String toString() {
        return "MeteringInfo(numEvents=" + this.a + ", threshold=" + this.b + ", eventType=" + this.c + ", resourceId=" + this.d + ", userId=" + this.e + ", reason=" + this.f + ")";
    }
}
