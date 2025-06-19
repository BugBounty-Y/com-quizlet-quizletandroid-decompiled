package com.quizlet.partskit.widgets.icon;

import android.content.Context;
import android.graphics.Typeface;
import android.text.SpannableString;
import androidx.navigation.compose.w;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

/* loaded from: classes3.dex */
public final class b {
    public final u a;

    public b(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = l.b(new w(context, 7));
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [java.lang.Object, java.util.Map] */
    public final SpannableString a(String iconStringKey) {
        Intrinsics.checkNotNullParameter(iconStringKey, "iconStringKey");
        try {
            String str = (String) com.quizlet.generated.sharedconfig.b.b.get(iconStringKey);
            Intrinsics.d(str);
            SpannableString spannableString = new SpannableString(new String(new int[]{Integer.decode("#e".concat(str)).intValue()}, 0, 1));
            spannableString.setSpan(new InlineFontTypefaceSpan((Typeface) this.a.getValue()), 0, spannableString.length(), 33);
            return spannableString;
        } catch (RuntimeException e) {
            c.a.e(e);
            return new SpannableString("");
        }
    }
}
