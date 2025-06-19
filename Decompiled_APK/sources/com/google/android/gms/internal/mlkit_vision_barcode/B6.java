package com.google.android.gms.internal.mlkit_vision_barcode;

import android.graphics.Paint;
import android.icu.text.DecimalFormatSymbols;
import android.os.Build;
import android.text.TextDirectionHeuristic;
import android.text.TextDirectionHeuristics;
import android.text.TextPaint;
import android.text.method.PasswordTransformationMethod;
import android.view.ActionMode;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatTextView;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B6 {
    public static final /* synthetic */ int a = 0;

    public static androidx.core.text.c a(AppCompatTextView appCompatTextView) {
        int i = Build.VERSION.SDK_INT;
        if (i >= 28) {
            return new androidx.core.text.c(androidx.arch.core.executor.d.m(appCompatTextView));
        }
        TextPaint textPaint = new TextPaint(appCompatTextView.getPaint());
        TextDirectionHeuristic textDirectionHeuristic = TextDirectionHeuristics.FIRSTSTRONG_LTR;
        int breakStrategy = appCompatTextView.getBreakStrategy();
        int hyphenationFrequency = appCompatTextView.getHyphenationFrequency();
        if (appCompatTextView.getTransformationMethod() instanceof PasswordTransformationMethod) {
            textDirectionHeuristic = TextDirectionHeuristics.LTR;
        } else {
            if (i < 28 || (appCompatTextView.getInputType() & 15) != 3) {
                boolean z = appCompatTextView.getLayoutDirection() == 1;
                switch (appCompatTextView.getTextDirection()) {
                    case 2:
                        textDirectionHeuristic = TextDirectionHeuristics.ANYRTL_LTR;
                        break;
                    case 3:
                        textDirectionHeuristic = TextDirectionHeuristics.LTR;
                        break;
                    case 4:
                        textDirectionHeuristic = TextDirectionHeuristics.RTL;
                        break;
                    case 5:
                        textDirectionHeuristic = TextDirectionHeuristics.LOCALE;
                        break;
                    case 6:
                        break;
                    case 7:
                        textDirectionHeuristic = TextDirectionHeuristics.FIRSTSTRONG_RTL;
                        break;
                    default:
                        if (z) {
                            textDirectionHeuristic = TextDirectionHeuristics.FIRSTSTRONG_RTL;
                            break;
                        }
                        break;
                }
            } else {
                byte directionality = Character.getDirectionality(androidx.arch.core.executor.d.c(DecimalFormatSymbols.getInstance(appCompatTextView.getTextLocale()))[0].codePointAt(0));
                textDirectionHeuristic = (directionality == 1 || directionality == 2) ? TextDirectionHeuristics.RTL : TextDirectionHeuristics.LTR;
            }
        }
        return new androidx.core.text.c(textPaint, textDirectionHeuristic, breakStrategy, hyphenationFrequency);
    }

    public static void b(TextView textView, int i) {
        AbstractC3242q6.f(i);
        if (Build.VERSION.SDK_INT >= 28) {
            androidx.arch.core.executor.d.q(textView, i);
            return;
        }
        Paint.FontMetricsInt fontMetricsInt = textView.getPaint().getFontMetricsInt();
        int i2 = textView.getIncludeFontPadding() ? fontMetricsInt.top : fontMetricsInt.ascent;
        if (i > Math.abs(i2)) {
            textView.setPadding(textView.getPaddingLeft(), i + i2, textView.getPaddingRight(), textView.getPaddingBottom());
        }
    }

    public static void c(TextView textView, int i) {
        AbstractC3242q6.f(i);
        Paint.FontMetricsInt fontMetricsInt = textView.getPaint().getFontMetricsInt();
        int i2 = textView.getIncludeFontPadding() ? fontMetricsInt.bottom : fontMetricsInt.descent;
        if (i > Math.abs(i2)) {
            textView.setPadding(textView.getPaddingLeft(), textView.getPaddingTop(), textView.getPaddingRight(), i - i2);
        }
    }

    public static void d(TextView textView, int i) {
        AbstractC3242q6.f(i);
        if (i != textView.getPaint().getFontMetricsInt(null)) {
            textView.setLineSpacing(i - r0, 1.0f);
        }
    }

    public static final com.quizlet.features.infra.models.a e(DBTerm dBTerm, com.quizlet.generated.enums.O1 side) {
        Intrinsics.checkNotNullParameter(dBTerm, "<this>");
        Intrinsics.checkNotNullParameter(side, "side");
        return new com.quizlet.features.infra.models.a(dBTerm.getText(side), dBTerm.getLanguageCode(side), dBTerm.getRichText(side), (side == com.quizlet.generated.enums.O1.DEFINITION && dBTerm.hasDefinitionImage()) ? false : true);
    }

    public static final com.quizlet.features.infra.models.a f(StudiableText studiableText, boolean z) {
        Intrinsics.checkNotNullParameter(studiableText, "<this>");
        return new com.quizlet.features.infra.models.a(studiableText.a, studiableText.b, studiableText.c, z);
    }

    public static final com.quizlet.features.infra.models.a g(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        return new com.quizlet.features.infra.models.a(str, null, null, false);
    }

    public static ActionMode.Callback h(ActionMode.Callback callback) {
        return callback instanceof androidx.core.widget.o ? ((androidx.core.widget.o) callback).a : callback;
    }

    public static ActionMode.Callback i(ActionMode.Callback callback, TextView textView) {
        return (Build.VERSION.SDK_INT > 27 || (callback instanceof androidx.core.widget.o) || callback == null) ? callback : new androidx.core.widget.o(callback, textView);
    }
}
