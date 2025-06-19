package com.quizlet.quizletandroid.util;

import android.content.Context;
import android.graphics.Typeface;
import android.text.SpannableString;
import androidx.navigation.compose.w;
import com.quizlet.partskit.widgets.icon.InlineFontTypefaceSpan;
import com.quizlet.quizletandroid.R;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.u;

/* loaded from: classes3.dex */
public final class f implements com.quizlet.qutils.language.a {
    public static final List d = B.j("ja", "zh", "th", "km", "bo");
    public final com.quizlet.partskit.widgets.icon.b a;
    public final u b;
    public final u c;

    public f(Context context, com.quizlet.partskit.widgets.icon.b iconProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(iconProvider, "iconProvider");
        this.a = iconProvider;
        this.b = kotlin.l.b(new w(context, 9));
        this.c = kotlin.l.b(new w(context, 10));
    }

    public static int b(String str) {
        if (str != null) {
            int iHashCode = str.hashCode();
            if (iHashCode != 3239) {
                if (iHashCode != 3374) {
                    if (iHashCode != 3500) {
                        if (iHashCode != 3052493) {
                            if (iHashCode == 3344136 && str.equals("math")) {
                                return R.font.libertinus_sans_regular;
                            }
                        } else if (str.equals("chem")) {
                            return R.font.libertinus_sans_regular;
                        }
                    } else if (str.equals("my")) {
                        return R.font.tharlon;
                    }
                } else if (str.equals("iw")) {
                    return R.font.shlomo;
                }
            } else if (str.equals("el")) {
                return R.font.noto_sans;
            }
        }
        return com.quizlet.ui.resources.designsystem.generated.a.b;
    }

    public final String a(String str) {
        return (String) ((Map) this.c.getValue()).get(str);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00b6  */
    /* JADX WARN: Type inference failed for: r10v4, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r3v0, types: [android.text.SpannableString] */
    /* JADX WARN: Type inference failed for: r3v1, types: [java.lang.CharSequence] */
    /* JADX WARN: Type inference failed for: r3v4, types: [android.text.SpannableStringBuilder] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.text.SpannableString c(android.content.Context r10, java.lang.String r11, java.lang.String r12) {
        /*
            Method dump skipped, instructions count: 285
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.util.f.c(android.content.Context, java.lang.String, java.lang.String):android.text.SpannableString");
    }

    public final String d(String str) {
        return (String) ((Map) this.b.getValue()).get(str);
    }

    public final com.quizlet.qutils.language.e e(String wordLanguageCode, String definitionLanguageCode) {
        Intrinsics.checkNotNullParameter(wordLanguageCode, "wordLanguageCode");
        Intrinsics.checkNotNullParameter(definitionLanguageCode, "definitionLanguageCode");
        String strD = d(definitionLanguageCode);
        Locale locale = Locale.ROOT;
        String lowerCase = definitionLanguageCode.toLowerCase(locale);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        String lowerCase2 = wordLanguageCode.toLowerCase(locale);
        Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");
        if (!Intrinsics.b(lowerCase, lowerCase2)) {
            String lowerCase3 = definitionLanguageCode.toLowerCase(locale);
            Intrinsics.checkNotNullExpressionValue(lowerCase3, "toLowerCase(...)");
            String lowerCase4 = "??".toLowerCase(locale);
            Intrinsics.checkNotNullExpressionValue(lowerCase4, "toLowerCase(...)");
            if (!Intrinsics.b(lowerCase3, lowerCase4) && strD != null) {
                return new com.quizlet.qutils.language.c(strD);
            }
        }
        return com.quizlet.qutils.language.b.a;
    }

    public final com.quizlet.qutils.language.e f(String wordLanguageCode, String definitionLanguageCode) {
        Intrinsics.checkNotNullParameter(wordLanguageCode, "wordLanguageCode");
        Intrinsics.checkNotNullParameter(definitionLanguageCode, "definitionLanguageCode");
        String strD = d(wordLanguageCode);
        Locale locale = Locale.ROOT;
        String lowerCase = wordLanguageCode.toLowerCase(locale);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        String lowerCase2 = definitionLanguageCode.toLowerCase(locale);
        Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");
        if (!Intrinsics.b(lowerCase, lowerCase2)) {
            String lowerCase3 = wordLanguageCode.toLowerCase(locale);
            Intrinsics.checkNotNullExpressionValue(lowerCase3, "toLowerCase(...)");
            String lowerCase4 = "??".toLowerCase(locale);
            Intrinsics.checkNotNullExpressionValue(lowerCase4, "toLowerCase(...)");
            if (!Intrinsics.b(lowerCase3, lowerCase4) && strD != null) {
                return new com.quizlet.qutils.language.c(strD);
            }
        }
        return com.quizlet.qutils.language.d.a;
    }

    public final SpannableString g(String s) {
        Intrinsics.checkNotNullParameter(s, "s");
        com.quizlet.partskit.widgets.icon.b bVar = this.a;
        SpannableString spannableStringA = bVar.a("star");
        SpannableString spannableString = new SpannableString(s);
        int iL = StringsKt.L(s, spannableStringA.charAt(0), 0, false, 6);
        if (iL > -1) {
            spannableString.setSpan(new InlineFontTypefaceSpan((Typeface) bVar.a.getValue()), iL, iL + 1, 33);
        }
        return spannableString;
    }
}
