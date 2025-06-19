package androidx.compose.ui.graphics.vector;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.graphics.C0853m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class F extends D {
    public final C0864c b;
    public String c;
    public boolean d;
    public final C0862a e;
    public kotlin.jvm.internal.r f;
    public final InterfaceC0773a0 g;
    public C0853m h;
    public final InterfaceC0773a0 i;
    public long j;
    public float k;
    public float l;
    public final E m;

    public F(C0864c c0864c) {
        this.b = c0864c;
        c0864c.i = new E(this, 0);
        this.c = "";
        this.d = true;
        this.e = new C0862a();
        this.f = C0869h.c;
        this.g = C0776c.z(null);
        this.i = C0776c.z(new androidx.compose.ui.geometry.e(0L));
        this.j = 9205357640488583168L;
        this.k = 1.0f;
        this.l = 1.0f;
        this.m = new E(this, 1);
    }

    @Override // androidx.compose.ui.graphics.vector.D
    public final void a(androidx.compose.ui.graphics.drawscope.d dVar) {
        e(dVar, 1.0f, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0069  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(androidx.compose.ui.graphics.drawscope.d r36, float r37, androidx.compose.ui.graphics.AbstractC0874w r38) {
        /*
            Method dump skipped, instructions count: 448
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.graphics.vector.F.e(androidx.compose.ui.graphics.drawscope.d, float, androidx.compose.ui.graphics.w):void");
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Params: \tname: ");
        sb.append(this.c);
        sb.append("\n\tviewportWidth: ");
        InterfaceC0773a0 interfaceC0773a0 = this.i;
        sb.append(androidx.compose.ui.geometry.e.d(((androidx.compose.ui.geometry.e) ((L0) interfaceC0773a0).getValue()).a));
        sb.append("\n\tviewportHeight: ");
        sb.append(androidx.compose.ui.geometry.e.b(((androidx.compose.ui.geometry.e) ((L0) interfaceC0773a0).getValue()).a));
        sb.append("\n");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }
}
