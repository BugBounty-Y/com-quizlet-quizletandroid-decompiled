package org.wordpress.aztec.spans;

import android.text.TextPaint;
import android.text.style.CharacterStyle;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: org.wordpress.aztec.spans.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5171t extends CharacterStyle {
    public final String a;
    public boolean b;

    public C5171t(String text) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint tp) {
        Intrinsics.checkNotNullParameter(tp, "tp");
    }
}
