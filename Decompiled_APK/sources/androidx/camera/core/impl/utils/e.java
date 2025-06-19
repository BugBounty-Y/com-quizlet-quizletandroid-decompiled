package androidx.camera.core.impl.utils;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.SpannedString;
import android.text.style.ForegroundColorSpan;
import androidx.activity.L;
import androidx.activity.M;
import androidx.activity.u;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3224o6;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.text.URLSpanNoUnderline;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class e {
    public static volatile Handler a;

    public static void a(L l, u uVar, Function1 onBackPressed) {
        Intrinsics.checkNotNullParameter(l, "<this>");
        Intrinsics.checkNotNullParameter(onBackPressed, "onBackPressed");
        l.a(uVar, new M(onBackPressed));
    }

    public static Handler b() {
        if (a != null) {
            return a;
        }
        synchronized (e.class) {
            try {
                if (a == null) {
                    a = AbstractC3224o6.b(Looper.getMainLooper());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return a;
    }

    public static final SpannedString c(Context context, int i, Integer num) {
        Intrinsics.checkNotNullParameter(context, "context");
        String string = context.getString(R.string.accepting_tos_terms_of_service);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(string);
        Intrinsics.checkNotNullParameter(spannableStringBuilder, "<this>");
        Intrinsics.checkNotNullParameter("https://quizlet.com/tos", DTBMetricsConfiguration.APSMETRICS_URL);
        String string2 = spannableStringBuilder.toString();
        URLSpanNoUnderline uRLSpanNoUnderline = new URLSpanNoUnderline("https://quizlet.com/tos");
        uRLSpanNoUnderline.a = string2;
        AbstractC3161h6.h(spannableStringBuilder, uRLSpanNoUnderline);
        int iA = com.quizlet.themes.extensions.a.a(context, i);
        Intrinsics.checkNotNullParameter(spannableStringBuilder, "<this>");
        AbstractC3161h6.h(spannableStringBuilder, new ForegroundColorSpan(iA));
        int i2 = com.quizlet.ui.resources.designsystem.generated.a.d;
        AbstractC3161h6.g(spannableStringBuilder, context, i2);
        String string3 = context.getString(R.string.accepting_tos_privacy_policy);
        Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
        SpannableStringBuilder spannableStringBuilder2 = new SpannableStringBuilder(string3);
        Intrinsics.checkNotNullParameter(spannableStringBuilder2, "<this>");
        Intrinsics.checkNotNullParameter("https://quizlet.com/privacy", DTBMetricsConfiguration.APSMETRICS_URL);
        String string4 = spannableStringBuilder2.toString();
        URLSpanNoUnderline uRLSpanNoUnderline2 = new URLSpanNoUnderline("https://quizlet.com/privacy");
        uRLSpanNoUnderline2.a = string4;
        AbstractC3161h6.h(spannableStringBuilder2, uRLSpanNoUnderline2);
        int iA2 = com.quizlet.themes.extensions.a.a(context, i);
        Intrinsics.checkNotNullParameter(spannableStringBuilder2, "<this>");
        AbstractC3161h6.h(spannableStringBuilder2, new ForegroundColorSpan(iA2));
        AbstractC3161h6.g(spannableStringBuilder2, context, i2);
        if (num != null) {
            int iIntValue = num.intValue();
            AbstractC3161h6.i(spannableStringBuilder2, context, iIntValue);
            AbstractC3161h6.i(spannableStringBuilder, context, iIntValue);
        }
        SpannedString spannedStringA = com.quizlet.uicommon.util.a.a(context.getString(R.string.signup_accepting_tos), spannableStringBuilder, spannableStringBuilder2);
        Intrinsics.checkNotNullExpressionValue(spannedStringA, "format(...)");
        return spannedStringA;
    }
}
