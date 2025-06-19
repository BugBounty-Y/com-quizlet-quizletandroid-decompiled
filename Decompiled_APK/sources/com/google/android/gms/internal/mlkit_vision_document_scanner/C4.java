package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.text.Spannable;
import android.text.SpannableString;
import android.text.method.LinkMovementMethod;
import android.widget.TextView;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class C4 {
    public static final /* synthetic */ int a = 0;

    public static void a(TextView view, String clickableText, Function0 listener) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(clickableText, "clickableText");
        Intrinsics.checkNotNullParameter(listener, "listener");
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(clickableText, "clickableText");
        Intrinsics.checkNotNullParameter(listener, "listener");
        CharSequence text = view.getText();
        String string = text.toString();
        androidx.compose.ui.text.platform.e eVar = new androidx.compose.ui.text.platform.e(listener);
        int iM = StringsKt.M(string, clickableText, 0, false, 6);
        int length = clickableText.length() + iM;
        if (iM == -1) {
            return;
        }
        if (text instanceof Spannable) {
            ((Spannable) text).setSpan(eVar, iM, length, 33);
        } else {
            SpannableString spannableStringValueOf = SpannableString.valueOf(text);
            spannableStringValueOf.setSpan(eVar, iM, length, 33);
            view.setText(spannableStringValueOf);
        }
        if (view.getMovementMethod() instanceof LinkMovementMethod) {
            return;
        }
        view.setMovementMethod(LinkMovementMethod.getInstance());
    }
}
