package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.e1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4124e1 {
    public final C4120d1 a;
    public final String b;
    public final String c;

    public C4124e1(C4120d1 c4120d1, String subtitle, String ctaButtonDeeplinkUrl) {
        Intrinsics.checkNotNullParameter("Bio 1b (evolution) practice midterm", "title");
        Intrinsics.checkNotNullParameter(subtitle, "subtitle");
        Intrinsics.checkNotNullParameter("Continue", "ctaButtonText");
        Intrinsics.checkNotNullParameter(ctaButtonDeeplinkUrl, "ctaButtonDeeplinkUrl");
        this.a = c4120d1;
        this.b = subtitle;
        this.c = ctaButtonDeeplinkUrl;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4124e1)) {
            return false;
        }
        C4124e1 c4124e1 = (C4124e1) obj;
        c4124e1.getClass();
        return Intrinsics.b(this.a, c4124e1.a) && Intrinsics.b(this.b, c4124e1.b) && Intrinsics.b(this.c, c4124e1.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((((this.b.hashCode() + (((-249589680) + (this.a == null ? 0 : r0.hashCode())) * 31)) * 31) - 502558521) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ProgressData(title=Bio 1b (evolution) practice midterm, progressBar=");
        sb.append(this.a);
        sb.append(", subtitle=");
        sb.append(this.b);
        sb.append(", ctaButtonText=Continue, ctaButtonDeeplinkUrl=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
