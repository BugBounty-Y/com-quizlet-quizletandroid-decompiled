package androidx.compose.ui.text;

import android.graphics.Canvas;
import android.text.TextUtils;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.U;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.ui.text.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0982b {
    public final androidx.compose.ui.text.platform.c a;
    public final int b;
    public final long c;
    public final androidx.compose.ui.text.android.x d;
    public final CharSequence e;
    public final Object f;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00d2  */
    /* JADX WARN: Type inference failed for: r1v35, types: [android.text.Spannable] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C0982b(androidx.compose.ui.text.platform.c r18, int r19, boolean r20, long r21) {
        /*
            Method dump skipped, instructions count: 806
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.C0982b.<init>(androidx.compose.ui.text.platform.c, int, boolean, long):void");
    }

    public final androidx.compose.ui.text.android.x a(int i, int i2, TextUtils.TruncateAt truncateAt, int i3, int i4, int i5, int i6, int i7) {
        w wVar;
        float fD = d();
        androidx.compose.ui.text.platform.c cVar = this.a;
        androidx.compose.ui.text.platform.a aVar = androidx.compose.ui.text.platform.b.a;
        y yVar = cVar.b.c;
        return new androidx.compose.ui.text.android.x(this.e, fD, cVar.g, i, truncateAt, cVar.l, (yVar == null || (wVar = yVar.b) == null) ? false : wVar.a, i3, i5, i6, i7, i4, i2, cVar.i);
    }

    public final float b() {
        return this.d.a();
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x00ae  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long c(androidx.compose.ui.geometry.c r12, int r13, androidx.camera.camera2.internal.s0 r14) {
        /*
            r11 = this;
            android.graphics.RectF r4 = androidx.compose.ui.graphics.F.y(r12)
            r12 = 1
            r8 = 0
            if (r13 != 0) goto L9
            goto Ld
        L9:
            if (r13 != r12) goto Ld
            r13 = r12
            goto Le
        Ld:
            r13 = r8
        Le:
            androidx.compose.ui.text.a r6 = new androidx.compose.ui.text.a
            r0 = 0
            r6.<init>(r14, r0)
            int r14 = android.os.Build.VERSION.SDK_INT
            r0 = 34
            r1 = r0
            androidx.compose.ui.text.android.x r0 = r11.d
            if (r14 < r1) goto L28
            r0.getClass()
            androidx.compose.ui.text.android.b r14 = androidx.compose.ui.text.android.b.a
            int[] r13 = r14.a(r0, r4, r13, r6)
            goto Lbe
        L28:
            com.google.android.gms.ads.internal.client.n r2 = r0.c()
            android.text.Layout r1 = r0.e
            if (r13 != r12) goto L40
            com.quizlet.data.interactor.school.b r13 = new com.quizlet.data.interactor.school.b
            java.lang.CharSequence r14 = r1.getText()
            androidx.compose.ui.text.android.selection.f r3 = r0.j()
            r5 = 4
            r13.<init>(r5, r14, r3)
        L3e:
            r5 = r13
            goto L57
        L40:
            java.lang.CharSequence r13 = r1.getText()
            r3 = 29
            if (r14 < r3) goto L51
            androidx.compose.ui.text.android.selection.c r14 = new androidx.compose.ui.text.android.selection.c
            android.text.TextPaint r3 = r0.a
            r14.<init>(r13, r3)
        L4f:
            r13 = r14
            goto L3e
        L51:
            androidx.compose.ui.text.android.selection.d r14 = new androidx.compose.ui.text.android.selection.d
            r14.<init>(r13)
            goto L4f
        L57:
            float r13 = r4.top
            int r13 = (int) r13
            int r13 = r1.getLineForVertical(r13)
            float r14 = r4.top
            float r3 = r0.e(r13)
            int r14 = (r14 > r3 ? 1 : (r14 == r3 ? 0 : -1))
            if (r14 <= 0) goto L6f
            int r13 = r13 + 1
            int r14 = r0.f
            if (r13 < r14) goto L6f
            goto Lae
        L6f:
            r3 = r13
            float r13 = r4.bottom
            int r13 = (int) r13
            int r13 = r1.getLineForVertical(r13)
            if (r13 != 0) goto L84
            float r14 = r4.bottom
            float r7 = r0.g(r8)
            int r14 = (r14 > r7 ? 1 : (r14 == r7 ? 0 : -1))
            if (r14 >= 0) goto L84
            goto Lae
        L84:
            r7 = 1
            int r14 = androidx.compose.ui.text.android.s.d(r0, r1, r2, r3, r4, r5, r6, r7)
        L89:
            r9 = r3
            r10 = -1
            if (r14 != r10) goto L97
            if (r9 >= r13) goto L97
            int r3 = r9 + 1
            r7 = 1
            int r14 = androidx.compose.ui.text.android.s.d(r0, r1, r2, r3, r4, r5, r6, r7)
            goto L89
        L97:
            if (r14 != r10) goto L9a
            goto Lae
        L9a:
            r7 = 0
            r3 = r13
            int r13 = androidx.compose.ui.text.android.s.d(r0, r1, r2, r3, r4, r5, r6, r7)
        La0:
            if (r13 != r10) goto Lac
            if (r9 >= r3) goto Lac
            int r3 = r3 + (-1)
            r7 = 0
            int r13 = androidx.compose.ui.text.android.s.d(r0, r1, r2, r3, r4, r5, r6, r7)
            goto La0
        Lac:
            if (r13 != r10) goto Lb0
        Lae:
            r13 = 0
            goto Lbe
        Lb0:
            int r14 = r14 + r12
            int r14 = r5.e(r14)
            int r13 = r13 - r12
            int r13 = r5.f(r13)
            int[] r13 = new int[]{r14, r13}
        Lbe:
            if (r13 != 0) goto Lc3
            long r12 = androidx.compose.ui.text.K.b
            return r12
        Lc3:
            r14 = r13[r8]
            r12 = r13[r12]
            long r12 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5.c(r14, r12)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.C0982b.c(androidx.compose.ui.geometry.c, int, androidx.camera.camera2.internal.s0):long");
    }

    public final float d() {
        return androidx.compose.ui.unit.a.h(this.c);
    }

    public final void e(InterfaceC0858s interfaceC0858s) {
        Canvas canvasA = AbstractC0845e.a(interfaceC0858s);
        androidx.compose.ui.text.android.x xVar = this.d;
        if (xVar.c) {
            canvasA.save();
            canvasA.clipRect(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, d(), b());
        }
        if (canvasA.getClipBounds(xVar.o)) {
            int i = xVar.g;
            if (i != 0) {
                canvasA.translate(DefinitionKt.NO_Float_VALUE, i);
            }
            androidx.compose.ui.text.android.w wVar = androidx.compose.ui.text.android.y.a;
            wVar.a = canvasA;
            xVar.e.draw(wVar);
            if (i != 0) {
                canvasA.translate(DefinitionKt.NO_Float_VALUE, (-1) * i);
            }
        }
        if (xVar.c) {
            canvasA.restore();
        }
    }

    public final void f(InterfaceC0858s interfaceC0858s, long j, U u, androidx.compose.ui.text.style.j jVar, androidx.compose.ui.graphics.drawscope.e eVar) {
        androidx.compose.ui.text.platform.d dVar = this.a.g;
        int i = dVar.c;
        dVar.d(j);
        dVar.f(u);
        dVar.g(jVar);
        dVar.e(eVar);
        dVar.b(3);
        e(interfaceC0858s);
        dVar.b(i);
    }

    public final void g(InterfaceC0858s interfaceC0858s, AbstractC0857q abstractC0857q, float f, U u, androidx.compose.ui.text.style.j jVar, androidx.compose.ui.graphics.drawscope.e eVar) {
        androidx.compose.ui.text.platform.d dVar = this.a.g;
        int i = dVar.c;
        dVar.c(abstractC0857q, T4.a(d(), b()), f);
        dVar.f(u);
        dVar.g(jVar);
        dVar.e(eVar);
        dVar.b(3);
        e(interfaceC0858s);
        dVar.b(i);
    }
}
