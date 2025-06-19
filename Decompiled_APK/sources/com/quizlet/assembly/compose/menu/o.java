package com.quizlet.assembly.compose.menu;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o implements q {
    public final Object a;
    public final String b;
    public final androidx.compose.ui.graphics.painter.b c;
    public final androidx.compose.ui.graphics.painter.b d;
    public final boolean e;
    public final p f;
    public final boolean g;

    public o(Object obj, String title, androidx.compose.ui.graphics.painter.b bVar, androidx.compose.ui.graphics.painter.b bVar2, boolean z, p selectedState, boolean z2, int i) {
        bVar = (i & 4) != 0 ? null : bVar;
        bVar2 = (i & 8) != 0 ? null : bVar2;
        z = (i & 32) != 0 ? true : z;
        selectedState = (i & 64) != 0 ? p.d : selectedState;
        z2 = (i & 128) != 0 ? false : z2;
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(selectedState, "selectedState");
        this.a = obj;
        this.b = title;
        this.c = bVar;
        this.d = bVar2;
        this.e = z;
        this.f = selectedState;
        this.g = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.a, oVar.a) && Intrinsics.b(this.b, oVar.b) && Intrinsics.b(this.c, oVar.c) && Intrinsics.b(this.d, oVar.d) && this.e == oVar.e && this.f == oVar.f && this.g == oVar.g;
    }

    public final int hashCode() {
        Object obj = this.a;
        int iE = d0.e((obj == null ? 0 : obj.hashCode()) * 31, 31, this.b);
        androidx.compose.ui.graphics.painter.b bVar = this.c;
        int iHashCode = (iE + (bVar == null ? 0 : bVar.hashCode())) * 31;
        androidx.compose.ui.graphics.painter.b bVar2 = this.d;
        return Boolean.hashCode(this.g) + ((this.f.hashCode() + d0.g(d0.g((iHashCode + (bVar2 == null ? 0 : bVar2.hashCode())) * 31, 31, false), 31, this.e)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Primary(option=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", leadingIcon=");
        sb.append(this.c);
        sb.append(", trailingIcon=");
        sb.append(this.d);
        sb.append(", hasChildMenus=false, isEnabled=");
        sb.append(this.e);
        sb.append(", selectedState=");
        sb.append(this.f);
        sb.append(", isDestructive=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}
