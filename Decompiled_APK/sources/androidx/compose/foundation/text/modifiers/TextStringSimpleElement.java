package androidx.compose.foundation.text.modifiers;

import androidx.compose.animation.d0;
import androidx.compose.ui.node.T;
import androidx.compose.ui.text.L;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class TextStringSimpleElement extends T {
    public final String b;
    public final L c;
    public final androidx.compose.ui.text.font.i d;
    public final int e;
    public final boolean f;
    public final int g;
    public final int h;

    public TextStringSimpleElement(String str, L l, androidx.compose.ui.text.font.i iVar, int i, boolean z, int i2, int i3) {
        this.b = str;
        this.c = l;
        this.d = iVar;
        this.e = i;
        this.f = z;
        this.g = i2;
        this.h = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TextStringSimpleElement)) {
            return false;
        }
        TextStringSimpleElement textStringSimpleElement = (TextStringSimpleElement) obj;
        textStringSimpleElement.getClass();
        return Intrinsics.b(this.b, textStringSimpleElement.b) && Intrinsics.b(this.c, textStringSimpleElement.c) && Intrinsics.b(this.d, textStringSimpleElement.d) && this.e == textStringSimpleElement.e && this.f == textStringSimpleElement.f && this.g == textStringSimpleElement.g && this.h == textStringSimpleElement.h;
    }

    public final int hashCode() {
        return (((d0.g(d0.b(this.e, (this.d.hashCode() + ((this.c.hashCode() + (this.b.hashCode() * 31)) * 31)) * 31, 31), 31, this.f) + this.g) * 31) + this.h) * 31;
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        p pVar = new p();
        pVar.n = this.b;
        pVar.o = this.c;
        pVar.p = this.d;
        pVar.q = this.e;
        pVar.r = this.f;
        pVar.s = this.g;
        pVar.t = this.h;
        return pVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0029  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x002b  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:48:? A[RETURN, SYNTHETIC] */
    @Override // androidx.compose.ui.node.T
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n(androidx.compose.ui.p r14) {
        /*
            r13 = this;
            androidx.compose.foundation.text.modifiers.p r14 = (androidx.compose.foundation.text.modifiers.p) r14
            r14.getClass()
            androidx.compose.ui.text.L r0 = r14.o
            r1 = 0
            r2 = 1
            androidx.compose.ui.text.L r3 = r13.c
            if (r3 == r0) goto L1a
            androidx.compose.ui.text.D r4 = r3.a
            androidx.compose.ui.text.D r0 = r0.a
            boolean r0 = r4.b(r0)
            if (r0 == 0) goto L18
            goto L1d
        L18:
            r0 = r2
            goto L1e
        L1a:
            r3.getClass()
        L1d:
            r0 = r1
        L1e:
            java.lang.String r4 = r14.n
            java.lang.String r5 = r13.b
            boolean r4 = kotlin.jvm.internal.Intrinsics.b(r4, r5)
            r6 = 0
            if (r4 == 0) goto L2b
            r4 = r1
            goto L30
        L2b:
            r14.n = r5
            r14.x = r6
            r4 = r2
        L30:
            androidx.compose.ui.text.L r5 = r14.o
            boolean r5 = r5.d(r3)
            r5 = r5 ^ r2
            r14.o = r3
            int r3 = r14.t
            int r7 = r13.h
            if (r3 == r7) goto L42
            r14.t = r7
            r5 = r2
        L42:
            int r3 = r14.s
            int r7 = r13.g
            if (r3 == r7) goto L4b
            r14.s = r7
            r5 = r2
        L4b:
            boolean r3 = r14.r
            boolean r7 = r13.f
            if (r3 == r7) goto L54
            r14.r = r7
            r5 = r2
        L54:
            androidx.compose.ui.text.font.i r3 = r14.p
            androidx.compose.ui.text.font.i r7 = r13.d
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r7)
            if (r3 != 0) goto L61
            r14.p = r7
            r5 = r2
        L61:
            int r3 = r14.q
            int r7 = r13.e
            if (r3 != r7) goto L69
            r2 = r5
            goto L6b
        L69:
            r14.q = r7
        L6b:
            if (r4 != 0) goto L6f
            if (r2 == 0) goto La8
        L6f:
            androidx.compose.foundation.text.modifiers.e r3 = r14.M0()
            java.lang.String r5 = r14.n
            androidx.compose.ui.text.L r7 = r14.o
            androidx.compose.ui.text.font.i r8 = r14.p
            int r9 = r14.q
            boolean r10 = r14.r
            int r11 = r14.s
            int r12 = r14.t
            r3.a = r5
            r3.b = r7
            r3.c = r8
            r3.d = r9
            r3.e = r10
            r3.f = r11
            r3.g = r12
            r3.j = r6
            r3.n = r6
            r3.o = r6
            r5 = -1
            r3.q = r5
            r3.r = r5
            long r5 = com.google.android.gms.internal.mlkit_vision_barcode.L5.m(r1, r1, r1, r1)
            r3.p = r5
            long r5 = com.google.android.gms.internal.mlkit_vision_barcode.R5.a(r1, r1)
            r3.l = r5
            r3.k = r1
        La8:
            boolean r1 = r14.m
            if (r1 != 0) goto Lad
            goto Lc7
        Lad:
            if (r4 != 0) goto Lb5
            if (r0 == 0) goto Lb8
            androidx.compose.foundation.text.modifiers.o r1 = r14.w
            if (r1 == 0) goto Lb8
        Lb5:
            androidx.compose.ui.node.AbstractC0910f.p(r14)
        Lb8:
            if (r4 != 0) goto Lbc
            if (r2 == 0) goto Lc2
        Lbc:
            androidx.compose.ui.node.AbstractC0910f.o(r14)
            androidx.compose.ui.node.AbstractC0910f.n(r14)
        Lc2:
            if (r0 == 0) goto Lc7
            androidx.compose.ui.node.AbstractC0910f.n(r14)
        Lc7:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.modifiers.TextStringSimpleElement.n(androidx.compose.ui.p):void");
    }
}
