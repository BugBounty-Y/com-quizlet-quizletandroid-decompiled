package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class M0 implements O0 {
    public final String a;
    public final String b;
    public final String c;
    public final K0 d;
    public final List e;
    public final S f;

    public M0(String practiceTestId, String questionBankId, String name, K0 configuration, List questions, S s) {
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(questions, "questions");
        this.a = practiceTestId;
        this.b = questionBankId;
        this.c = name;
        this.d = configuration;
        this.e = questions;
        this.f = s;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M0)) {
            return false;
        }
        M0 m0 = (M0) obj;
        return Intrinsics.b(this.a, m0.a) && Intrinsics.b(this.b, m0.b) && Intrinsics.b(this.c, m0.c) && Intrinsics.b(this.d, m0.d) && Intrinsics.b(this.e, m0.e) && Intrinsics.b(this.f, m0.f);
    }

    public final int hashCode() {
        int iF = androidx.compose.animation.d0.f((this.d.hashCode() + androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c)) * 31, 31, this.e);
        S s = this.f;
        return iF + (s == null ? 0 : s.hashCode());
    }

    public final String toString() {
        return "PracticeTest(practiceTestId=" + this.a + ", questionBankId=" + this.b + ", name=" + this.c + ", configuration=" + this.d + ", questions=" + this.e + ", entitlementData=" + this.f + ")";
    }
}
