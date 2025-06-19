package com.quizlet.features.flashcards.helpers;

import androidx.compose.ui.text.C0995g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final C0995g a;
    public final androidx.compose.ui.graphics.painter.b b;
    public final String c;

    public a(C0995g text, androidx.compose.ui.graphics.painter.b bVar, String str) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
        this.b = bVar;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        androidx.compose.ui.graphics.painter.b bVar = this.b;
        int iHashCode2 = (iHashCode + (bVar == null ? 0 : bVar.hashCode())) * 31;
        String str = this.c;
        return iHashCode2 + (str != null ? str.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsOnboardingInfo(text=");
        sb.append((Object) this.a);
        sb.append(", icon=");
        sb.append(this.b);
        sb.append(", iconContentDescription=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
