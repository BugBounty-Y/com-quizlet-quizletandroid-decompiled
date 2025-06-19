package androidx.compose.foundation.text;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0490g0 {
    public static final C0490g0 e = new C0490g0(0, 0, 127);
    public final int a;
    public final Boolean b;
    public final int c;
    public final int d;

    public C0490g0(int i, int i2, int i3) {
        Boolean bool = Boolean.FALSE;
        int i4 = (i3 & 1) != 0 ? -1 : 2;
        bool = (i3 & 2) != 0 ? null : bool;
        i = (i3 & 4) != 0 ? 0 : i;
        i2 = (i3 & 8) != 0 ? -1 : i2;
        this.a = i4;
        this.b = bool;
        this.c = i;
        this.d = i2;
    }

    public final androidx.compose.ui.text.input.m a(boolean z) {
        int i = this.a;
        androidx.compose.ui.text.input.n nVar = new androidx.compose.ui.text.input.n(i);
        if (i == -1) {
            nVar = null;
        }
        int i2 = nVar != null ? nVar.a : 0;
        Boolean bool = this.b;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : true;
        int i3 = this.c;
        androidx.compose.ui.text.input.o oVar = new androidx.compose.ui.text.input.o(i3);
        if (i3 == 0) {
            oVar = null;
        }
        int i4 = oVar != null ? oVar.a : 1;
        int i5 = this.d;
        androidx.compose.ui.text.input.l lVar = i5 != -1 ? new androidx.compose.ui.text.input.l(i5) : null;
        return new androidx.compose.ui.text.input.m(z, i2, zBooleanValue, i4, lVar != null ? lVar.a : 1, androidx.compose.ui.text.intl.b.c);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0490g0)) {
            return false;
        }
        C0490g0 c0490g0 = (C0490g0) obj;
        return this.a == c0490g0.a && Intrinsics.b(this.b, c0490g0.b) && this.c == c0490g0.c && this.d == c0490g0.d;
    }

    public final int hashCode() {
        int iHashCode = Integer.hashCode(this.a) * 31;
        Boolean bool = this.b;
        return androidx.compose.animation.d0.b(this.d, androidx.compose.animation.d0.b(this.c, (iHashCode + (bool != null ? bool.hashCode() : 0)) * 31, 31), 29791);
    }

    public final String toString() {
        return "KeyboardOptions(capitalization=" + ((Object) androidx.compose.ui.text.input.n.a(this.a)) + ", autoCorrectEnabled=" + this.b + ", keyboardType=" + ((Object) androidx.compose.ui.text.input.o.a(this.c)) + ", imeAction=" + ((Object) androidx.compose.ui.text.input.l.a(this.d)) + ", platformImeOptions=nullshowKeyboardOnFocus=null, hintLocales=null)";
    }
}
