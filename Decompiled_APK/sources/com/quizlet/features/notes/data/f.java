package com.quizlet.features.notes.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final String a;
    public final String b;
    public final String c;
    public final boolean d;
    public final x e;
    public final androidx.compose.ui.graphics.painter.b f;

    public /* synthetic */ f(String str, String str2, String str3, x xVar, androidx.compose.ui.graphics.painter.b bVar, int i) {
        this(str, str2, (i & 4) != 0 ? null : str3, true, xVar, bVar);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c) && this.d == fVar.d && Intrinsics.b(this.e, fVar.e) && Intrinsics.b(this.f, fVar.f);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return this.f.hashCode() + ((this.e.hashCode() + d0.g((iE + (str == null ? 0 : str.hashCode())) * 31, 31, this.d)) * 31);
    }

    public final String toString() {
        return "ScanNotesErrorData(headerText=" + this.a + ", buttonText=" + this.b + ", descriptionText=" + this.c + ", ctaVisible=" + this.d + ", errorReason=" + this.e + ", icon=" + this.f + ")";
    }

    public f(String headerText, String buttonText, String str, boolean z, x errorReason, androidx.compose.ui.graphics.painter.b icon) {
        Intrinsics.checkNotNullParameter(headerText, "headerText");
        Intrinsics.checkNotNullParameter(buttonText, "buttonText");
        Intrinsics.checkNotNullParameter(errorReason, "errorReason");
        Intrinsics.checkNotNullParameter(icon, "icon");
        this.a = headerText;
        this.b = buttonText;
        this.c = str;
        this.d = z;
        this.e = errorReason;
        this.f = icon;
    }
}
