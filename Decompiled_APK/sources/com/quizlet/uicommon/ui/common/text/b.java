package com.quizlet.uicommon.ui.common.text;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.SpannedString;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.quizlet.quizletandroid.R;
import com.quizlet.qutils.string.f;
import com.quizlet.qutils.string.g;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements g {
    public final f a;
    public final List b;

    public b(f resData, List clickableSubstrings) {
        Intrinsics.checkNotNullParameter(resData, "resData");
        Intrinsics.checkNotNullParameter(clickableSubstrings, "clickableSubstrings");
        this.a = resData;
        this.b = clickableSubstrings;
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
        CharSequence charSequenceC = this.a.c(context);
        List<c> list = this.b;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (c cVar : list) {
            cVar.getClass();
            Intrinsics.checkNotNullParameter(context, "context");
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(cVar.a.c(context));
            com.quizlet.ui.compose.modifiers.b click = new com.quizlet.ui.compose.modifiers.b(cVar, 1);
            Intrinsics.checkNotNullParameter(spannableStringBuilder, "<this>");
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(click, "click");
            AbstractC3161h6.h(spannableStringBuilder, new com.quizlet.uicommon.util.b(click, com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyLinkText), com.quizlet.themes.extensions.a.a(context, R.attr.AssemblyLinkTextPressed)));
            AbstractC3161h6.i(spannableStringBuilder, context, 1);
            arrayList.add(spannableStringBuilder);
        }
        SpannableStringBuilder[] spannableStringBuilderArr = (SpannableStringBuilder[]) arrayList.toArray(new SpannableStringBuilder[0]);
        SpannedString spannedStringA = com.quizlet.uicommon.util.a.a(charSequenceC, Arrays.copyOf(spannableStringBuilderArr, spannableStringBuilderArr.length));
        Intrinsics.checkNotNullExpressionValue(spannedStringA, "format(...)");
        return spannedStringA;
    }

    @Override // com.quizlet.qutils.string.g
    public final CharSequence d(InterfaceC0806l interfaceC0806l, int i) {
        return AbstractC3053s1.b(this, interfaceC0806l);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a.equals(bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClickableStringData(resData=");
        sb.append(this.a);
        sb.append(", clickableSubstrings=");
        return android.support.v4.media.session.a.n(")", sb, this.b);
    }
}
