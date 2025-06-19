package com.quizlet.features.practicetest.takingtest.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class F implements J {
    public final int a;
    public final int b;
    public final C4412f c;
    public final kotlinx.collections.immutable.e d;
    public final N e;
    public final InterfaceC4415i f;
    public final M g;
    public final boolean h;
    public final int i;

    public /* synthetic */ F(int i, int i2, C4412f c4412f, kotlinx.collections.immutable.e eVar, N n, InterfaceC4415i interfaceC4415i, M m, int i3) {
        this(i, i2, c4412f, eVar, (i3 & 16) != 0 ? null : n, (i3 & 32) != 0 ? null : interfaceC4415i, (i3 & 64) != 0 ? null : m, false);
    }

    public static F a(F f, boolean z) {
        int i = f.a;
        int i2 = f.b;
        C4412f currentQuestion = f.c;
        kotlinx.collections.immutable.e questionStatusList = f.d;
        N n = f.e;
        InterfaceC4415i interfaceC4415i = f.f;
        M m = f.g;
        f.getClass();
        Intrinsics.checkNotNullParameter(currentQuestion, "currentQuestion");
        Intrinsics.checkNotNullParameter(questionStatusList, "questionStatusList");
        return new F(i, i2, currentQuestion, questionStatusList, n, interfaceC4415i, m, z);
    }

    public final boolean b() {
        InterfaceC4415i interfaceC4415i = this.f;
        return (interfaceC4415i != null && interfaceC4415i.a()) || this.c.i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof F)) {
            return false;
        }
        F f = (F) obj;
        return this.a == f.a && this.b == f.b && Intrinsics.b(this.c, f.c) && Intrinsics.b(this.d, f.d) && Intrinsics.b(this.e, f.e) && Intrinsics.b(this.f, f.f) && Intrinsics.b(this.g, f.g) && this.h == f.h;
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + ((this.c.hashCode() + d0.b(this.b, Integer.hashCode(this.a) * 31, 31)) * 31)) * 31;
        N n = this.e;
        int iHashCode2 = (iHashCode + (n == null ? 0 : n.hashCode())) * 31;
        InterfaceC4415i interfaceC4415i = this.f;
        int iHashCode3 = (iHashCode2 + (interfaceC4415i == null ? 0 : interfaceC4415i.hashCode())) * 31;
        M m = this.g;
        return Boolean.hashCode(this.h) + ((iHashCode3 + (m != null ? m.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(currentQuestionIndex=");
        sb.append(this.a);
        sb.append(", totalRounds=");
        sb.append(this.b);
        sb.append(", currentQuestion=");
        sb.append(this.c);
        sb.append(", questionStatusList=");
        sb.append(this.d);
        sb.append(", configuration=");
        sb.append(this.e);
        sb.append(", currentAnswer=");
        sb.append(this.f);
        sb.append(", settings=");
        sb.append(this.g);
        sb.append(", isLoading=");
        return android.support.v4.media.session.a.o(")", sb, this.h);
    }

    public F(int i, int i2, C4412f currentQuestion, kotlinx.collections.immutable.e questionStatusList, N n, InterfaceC4415i interfaceC4415i, M m, boolean z) {
        Intrinsics.checkNotNullParameter(currentQuestion, "currentQuestion");
        Intrinsics.checkNotNullParameter(questionStatusList, "questionStatusList");
        this.a = i;
        this.b = i2;
        this.c = currentQuestion;
        this.d = questionStatusList;
        this.e = n;
        this.f = interfaceC4415i;
        this.g = m;
        this.h = z;
        this.i = i + 1;
    }
}
