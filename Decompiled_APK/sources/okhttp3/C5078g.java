package okhttp3;

import androidx.compose.animation.d0;
import androidx.transition.C1405h;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: okhttp3.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5078g {
    public final String a;
    public final String b;
    public final okio.k c;

    public C5078g(String pin) {
        Intrinsics.checkNotNullParameter("*.perimeterx.net", "pattern");
        Intrinsics.checkNotNullParameter(pin, "pin");
        if ((!kotlin.text.D.r("*.perimeterx.net", "*.", false) || StringsKt.M("*.perimeterx.net", "*", 1, false, 4) != -1) && ((!kotlin.text.D.r("*.perimeterx.net", "**.", false) || StringsKt.M("*.perimeterx.net", "*", 2, false, 4) != -1) && StringsKt.M("*.perimeterx.net", "*", 0, false, 6) != -1)) {
            throw new IllegalArgumentException("Unexpected pattern: ".concat("*.perimeterx.net").toString());
        }
        String strD = C1405h.d("*.perimeterx.net");
        if (strD == null) {
            throw new IllegalArgumentException("Invalid pattern: ".concat("*.perimeterx.net"));
        }
        this.a = strD;
        if (kotlin.text.D.r(pin, "sha1/", false)) {
            this.b = "sha1";
            okio.k kVar = okio.k.d;
            String strSubstring = pin.substring(5);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
            okio.k kVarF = com.quizlet.quizletandroid.ui.common.images.capture.b.f(strSubstring);
            if (kVarF == null) {
                throw new IllegalArgumentException("Invalid pin hash: ".concat(pin));
            }
            this.c = kVarF;
            return;
        }
        if (!kotlin.text.D.r(pin, "sha256/", false)) {
            throw new IllegalArgumentException("pins must start with 'sha256/' or 'sha1/': ".concat(pin));
        }
        this.b = "sha256";
        okio.k kVar2 = okio.k.d;
        String strSubstring2 = pin.substring(7);
        Intrinsics.checkNotNullExpressionValue(strSubstring2, "this as java.lang.String).substring(startIndex)");
        okio.k kVarF2 = com.quizlet.quizletandroid.ui.common.images.capture.b.f(strSubstring2);
        if (kVarF2 == null) {
            throw new IllegalArgumentException("Invalid pin hash: ".concat(pin));
        }
        this.c = kVarF2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C5078g)) {
            return false;
        }
        C5078g c5078g = (C5078g) obj;
        return Intrinsics.b(this.a, c5078g.a) && Intrinsics.b(this.b, c5078g.b) && Intrinsics.b(this.c, c5078g.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return this.b + '/' + this.c.a();
    }
}
