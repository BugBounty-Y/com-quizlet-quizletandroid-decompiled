package com.quizlet.learn.data.onboarding;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.onboarding.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4551a implements d {
    public final kotlinx.collections.immutable.e a;
    public final m b;
    public final u c;
    public final boolean d;

    public C4551a(kotlinx.collections.immutable.e goalOptions, boolean z) {
        k defaultGoal = k.d;
        s defaultKnowledge = s.d;
        Intrinsics.checkNotNullParameter(goalOptions, "goalOptions");
        Intrinsics.checkNotNullParameter(defaultGoal, "defaultGoal");
        Intrinsics.checkNotNullParameter(defaultKnowledge, "defaultKnowledge");
        this.a = goalOptions;
        this.b = defaultGoal;
        this.c = defaultKnowledge;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4551a)) {
            return false;
        }
        C4551a c4551a = (C4551a) obj;
        return Intrinsics.b(this.a, c4551a.a) && Intrinsics.b(this.b, c4551a.b) && Intrinsics.b(this.c, c4551a.c) && this.d == c4551a.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(goalOptions=");
        sb.append(this.a);
        sb.append(", defaultGoal=");
        sb.append(this.b);
        sb.append(", defaultKnowledge=");
        sb.append(this.c);
        sb.append(", shouldShowWriteMode=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
