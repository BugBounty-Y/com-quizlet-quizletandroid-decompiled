package com.google.android.gms.internal.mlkit_vision_camera;

import android.text.Editable;
import assistantMode.refactored.types.Checkpoint;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes2.dex */
public abstract class Y2 {
    public static Editable a(Editable text, boolean z) {
        Intrinsics.checkNotNullParameter(text, "text");
        int length = text.length();
        char c = C2.i;
        if (length == 0) {
            Object[] spans = text.getSpans(0, 0, org.wordpress.aztec.spans.D.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            if (spans.length != 0) {
                text.append(c);
                return text;
            }
        } else if (text.length() == 1 && text.charAt(0) == c && z) {
            Object[] spans2 = text.getSpans(0, 1, org.wordpress.aztec.spans.D.class);
            Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
            if (spans2.length == 0) {
                text.delete(0, 1);
                return text;
            }
        } else {
            char cCharAt = text.charAt(text.length() - 1);
            char c2 = C2.g;
            if (cCharAt == c2) {
                text.append(c);
                return text;
            }
            if (cCharAt != c) {
                while (true) {
                    int iP = StringsKt.P(text.toString(), c, 0, 6);
                    if (iP == -1) {
                        break;
                    }
                    text.delete(iP, iP + 1);
                }
            } else if (text.length() >= 2 && text.charAt(text.length() - 2) != c2) {
                text.delete(text.length() - 1, text.length());
                return text;
            }
        }
        return text;
    }

    public static int e(CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "charSequence");
        if (charSequence.length() == 0) {
            return 0;
        }
        return charSequence.charAt(charSequence.length() + (-1)) == C2.i ? charSequence.length() - 1 : charSequence.length();
    }

    public abstract Checkpoint b();

    public abstract com.quizlet.features.questiontypes.data.a c();

    public abstract assistantMode.refactored.types.d d();
}
