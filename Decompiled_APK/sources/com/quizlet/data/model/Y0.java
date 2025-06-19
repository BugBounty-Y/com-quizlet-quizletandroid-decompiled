package com.quizlet.data.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Y0 {
    public final ArrayList a;
    public final String b;
    public final int c;
    public final int d;
    public final K0 e;
    public final Long f;
    public final LinkedHashMap g;
    public final S h;
    public final boolean i;

    public Y0(ArrayList questions, String questionBankId, int i, int i2, K0 configuration, Long l, LinkedHashMap questionCounts, S s) {
        Intrinsics.checkNotNullParameter(questions, "questions");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
        this.a = questions;
        this.b = questionBankId;
        this.c = i;
        this.d = i2;
        this.e = configuration;
        this.f = l;
        this.g = questionCounts;
        this.h = s;
        this.i = s != null ? s.a : true;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Y0)) {
            return false;
        }
        Y0 y0 = (Y0) obj;
        return this.a.equals(y0.a) && this.b.equals(y0.b) && this.c == y0.c && this.d == y0.d && Intrinsics.b(this.e, y0.e) && Intrinsics.b(this.f, y0.f) && this.g.equals(y0.g) && Intrinsics.b(this.h, y0.h);
    }

    public final int hashCode() {
        int iHashCode = (this.e.hashCode() + androidx.compose.animation.d0.b(this.d, androidx.compose.animation.d0.b(this.c, androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31), 31)) * 31;
        Long l = this.f;
        int iHashCode2 = (this.g.hashCode() + ((iHashCode + (l == null ? 0 : l.hashCode())) * 31)) * 31;
        S s = this.h;
        return iHashCode2 + (s != null ? s.hashCode() : 0);
    }

    public final String toString() {
        return "PracticeTestResult(questions=" + this.a + ", questionBankId=" + this.b + ", durationSeconds=" + this.c + ", round=" + this.d + ", configuration=" + this.e + ", setId=" + this.f + ", questionCounts=" + this.g + ", entitlementData=" + this.h + ")";
    }
}
