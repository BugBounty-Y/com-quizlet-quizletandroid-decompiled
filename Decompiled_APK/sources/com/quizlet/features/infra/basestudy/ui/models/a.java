package com.quizlet.features.infra.basestudy.ui.models;

import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.painter.b;
import com.quizlet.features.universaluploadflow.viewmodel.c;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final String b;
    public final b c;
    public final String d;
    public final String e;
    public final Function0 f;

    public a(String headerText, String str, b icon, String iconContentDescription, String str2, Function0 onCtaButtonClicked) {
        Intrinsics.checkNotNullParameter(headerText, "headerText");
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(iconContentDescription, "iconContentDescription");
        Intrinsics.checkNotNullParameter(onCtaButtonClicked, "onCtaButtonClicked");
        this.a = headerText;
        this.b = str;
        this.c = icon;
        this.d = iconContentDescription;
        this.e = str2;
        this.f = onCtaButtonClicked;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && Intrinsics.b(this.e, aVar.e) && Intrinsics.b(this.f, aVar.f);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        int iE = d0.e((this.c.hashCode() + ((iHashCode + (str == null ? 0 : str.hashCode())) * 31)) * 31, 31, this.d);
        String str2 = this.e;
        return this.f.hashCode() + ((iE + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "ErrorUiData(headerText=" + this.a + ", subheaderText=" + this.b + ", icon=" + this.c + ", iconContentDescription=" + this.d + ", ctaButtonText=" + this.e + ", onCtaButtonClicked=" + this.f + ")";
    }

    public /* synthetic */ a(String str, String str2, b bVar, String str3, String str4, c cVar, int i) {
        this(str, (i & 2) != 0 ? null : str2, bVar, str3, (i & 16) != 0 ? null : str4, (i & 32) != 0 ? new com.quizlet.features.emailconfirmation.ui.composables.c(13) : cVar);
    }
}
