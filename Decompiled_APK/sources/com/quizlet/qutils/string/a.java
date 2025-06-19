package com.quizlet.qutils.string;

import android.content.Context;
import android.content.res.Resources;
import androidx.compose.animation.d0;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements g {
    public final int a;

    public a(int i) {
        this.a = i;
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
        String string = context.getResources().getString(R.string.explanation_solution_tab_title_default);
        String[] stringArray = context.getResources().getStringArray(R.array.explanation_solution_tab_title);
        Intrinsics.checkNotNullExpressionValue(stringArray, "getStringArray(...)");
        int i = this.a;
        String str = (String) C4933y.F(i, stringArray);
        if (str != null) {
            return str;
        }
        if (string != null) {
            return string;
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Index (", ") is out of bounds for array (");
        sbV.append(stringArray);
        sbV.append(")");
        throw new IndexOutOfBoundsException(sbV.toString());
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3053s1.b(this, interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        aVar.getClass();
        return this.a == aVar.a && Integer.valueOf(R.string.explanation_solution_tab_title_default).equals(Integer.valueOf(R.string.explanation_solution_tab_title_default));
    }

    public final int hashCode() {
        return Integer.valueOf(R.string.explanation_solution_tab_title_default).hashCode() + d0.b(this.a, Integer.hashCode(R.array.explanation_solution_tab_title) * 31, 31);
    }

    public final String toString() {
        return "ArrayIndexSingularResData(arrayResId=2130903053, index=" + this.a + ", defaultResId=" + Integer.valueOf(R.string.explanation_solution_tab_title_default) + ")";
    }
}
