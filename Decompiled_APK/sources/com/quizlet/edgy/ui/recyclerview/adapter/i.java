package com.quizlet.edgy.ui.recyclerview.adapter;

import androidx.compose.animation.d0;
import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i implements com.quizlet.baserecyclerview.a {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final long e;
    public final com.quizlet.qutils.string.f f;

    public i(long j, String name, String city, String state) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(city, "city");
        Intrinsics.checkNotNullParameter(state, "state");
        this.a = j;
        this.b = name;
        this.c = city;
        this.d = state;
        this.e = j;
        Object[] args = {city, state};
        Intrinsics.checkNotNullParameter(args, "args");
        this.f = new com.quizlet.qutils.string.f(R.string.edgy_flow_city_and_state, C4933y.P(args));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && Intrinsics.b(this.b, iVar.b) && Intrinsics.b(this.c, iVar.c) && Intrinsics.b(this.d, iVar.d);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Long.valueOf(this.e);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SearchSchoolItem(id=");
        sb.append(this.a);
        sb.append(", name=");
        sb.append(this.b);
        sb.append(", city=");
        sb.append(this.c);
        sb.append(", state=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
