package com.quizlet.richtext.model;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PmText {
    public final String a;
    public final List b;
    public final String c;
    public final String d;
    public final List e;

    public PmText(String type, String textValue, List list) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(textValue, "text");
        Intrinsics.checkNotNullParameter(textValue, "textValue");
        this.a = textValue;
        this.b = list;
        this.c = type;
        this.d = textValue;
        this.e = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PmText)) {
            return false;
        }
        PmText pmText = (PmText) obj;
        return Intrinsics.b(this.c, pmText.c) && Intrinsics.b(this.d, pmText.d) && Intrinsics.b(this.e, pmText.e);
    }

    public final int hashCode() {
        int iE = d0.e(this.c.hashCode() * 31, 31, this.d);
        List list = this.e;
        return iE + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PmText(type=");
        sb.append(this.c);
        sb.append(", text=");
        sb.append(this.d);
        sb.append(", marks=");
        return android.support.v4.media.session.a.n(")", sb, this.e);
    }
}
