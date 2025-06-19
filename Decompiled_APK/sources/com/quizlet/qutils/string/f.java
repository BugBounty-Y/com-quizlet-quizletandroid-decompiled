package com.quizlet.qutils.string;

import android.content.Context;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import java.util.Arrays;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements g {
    public final int a;
    public final List b;

    public f(int i, List list) {
        this.a = i;
        this.b = list;
    }

    @Override // com.quizlet.qutils.string.g
    public final String a(Context context) {
        return AbstractC3053s1.e(this, context);
    }

    @Override // com.quizlet.qutils.string.g
    public final String b(InterfaceC0806l interfaceC0806l) {
        return AbstractC3053s1.g(this, interfaceC0806l);
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence c(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        int i = this.a;
        List list = this.b;
        if (list == null || list.isEmpty()) {
            String string = context.getString(i);
            Intrinsics.d(string);
            return string;
        }
        Object[] array = AbstractC3058t1.b(context, list).toArray(new Object[0]);
        String string2 = context.getString(i, Arrays.copyOf(array, array.length));
        Intrinsics.d(string2);
        return string2;
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3053s1.b(this, interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b);
    }

    public final int hashCode() {
        int iHashCode = Integer.hashCode(this.a) * 31;
        List list = this.b;
        return iHashCode + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        return "SingularStringResData(resId=" + this.a + ", args=" + this.b + ")";
    }
}
