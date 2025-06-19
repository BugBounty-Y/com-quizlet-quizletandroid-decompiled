package com.quizlet.ui.models.search;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final int a;
    public final d b;
    public final int c;

    public e(int i, d time, int i2) {
        Intrinsics.checkNotNullParameter(time, "time");
        this.a = i;
        this.b = time;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && this.b == eVar.b && this.c == eVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + ((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SocialSignalsUiModel(numStudiers=");
        sb.append(this.a);
        sb.append(", time=");
        sb.append(this.b);
        sb.append(", days=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
