package com.quizlet.upgrade.data;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.SpannedString;
import android.text.style.StyleSpan;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.upgrade.data.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4841i implements com.quizlet.qutils.string.g {
    public final int a;
    public final com.quizlet.qutils.string.f b;
    public final com.quizlet.qutils.string.d c;

    public C4841i(int i) {
        this.a = i;
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        this.b = new com.quizlet.qutils.string.f(R.string.free_trial_with_annual, C4933y.P(args));
        Object[] args2 = {Integer.valueOf(i)};
        Intrinsics.checkNotNullParameter(args2, "args");
        this.c = new com.quizlet.qutils.string.d(R.plurals.free_num_day_trial, i, C4933y.P(args2));
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
        com.quizlet.qutils.string.d dVar = this.c;
        dVar.getClass();
        String strE = AbstractC3053s1.e(dVar, context);
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(strE);
        spannableStringBuilder.setSpan(new StyleSpan(1), 0, strE.length(), 33);
        com.quizlet.qutils.string.f fVar = this.b;
        fVar.getClass();
        SpannedString spannedStringA = com.quizlet.uicommon.util.a.a(AbstractC3053s1.e(fVar, context), spannableStringBuilder);
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
        return (obj instanceof C4841i) && this.a == ((C4841i) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("SeePlansFreeTrialString(freeTrialDuration="), this.a, ")");
    }
}
