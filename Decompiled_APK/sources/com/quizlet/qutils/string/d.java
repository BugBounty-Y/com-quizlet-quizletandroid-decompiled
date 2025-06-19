package com.quizlet.qutils.string;

import android.content.Context;
import android.content.res.Resources;
import androidx.compose.animation.d0;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements g {
    public final int a;
    public final int b;
    public final List c;

    public d(int i, int i2, List list) {
        this.a = i;
        this.b = i2;
        this.c = list;
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
    public final CharSequence c(Context context) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(context, "context");
        int i = this.b;
        int i2 = this.a;
        List list = this.c;
        if (list == null || list.isEmpty()) {
            String quantityString = context.getResources().getQuantityString(i2, i);
            Intrinsics.d(quantityString);
            return quantityString;
        }
        ArrayList arrayListB = AbstractC3058t1.b(context, list);
        Resources resources = context.getResources();
        Object[] array = arrayListB.toArray(new Object[0]);
        String quantityString2 = resources.getQuantityString(i2, i, Arrays.copyOf(array, array.length));
        Intrinsics.d(quantityString2);
        return quantityString2;
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3053s1.b(this, interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b && Intrinsics.b(this.c, dVar.c);
    }

    public final int hashCode() {
        int iB = d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
        List list = this.c;
        return iB + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PluralStringResData(resId=");
        sb.append(this.a);
        sb.append(", quantity=");
        sb.append(this.b);
        sb.append(", args=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }
}
