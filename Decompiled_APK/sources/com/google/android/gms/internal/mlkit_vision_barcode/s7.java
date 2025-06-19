package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3673m4;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.AbstractC4387f;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4392k;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class s7 {
    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(958880567);
        if ((((c0814p.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar, "outlineLoading");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.q();
            float f = com.quizlet.ui.resources.designsystem.generated.j.i;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarC2 = androidx.compose.foundation.layout.K0.c(nVar, 1.0f);
            mVar.s();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.h;
            S5.d(f, AbstractC0382e.y(qVarC2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, 7), null, c0814p, 0);
            mVar.s();
            androidx.compose.ui.q qVarC3 = androidx.compose.foundation.layout.K0.c(nVar, 0.75f);
            mVar.u();
            float f3 = com.quizlet.ui.resources.designsystem.generated.j.g;
            S5.d(f2, AbstractC0382e.y(qVarC3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f3, 7), null, c0814p, 0);
            mVar.s();
            androidx.compose.ui.q qVarC4 = androidx.compose.foundation.layout.K0.c(nVar, 0.75f);
            mVar.u();
            S5.d(f2, AbstractC0382e.y(qVarC4, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f3, 7), null, c0814p, 0);
            mVar.s();
            S5.d(f2, androidx.compose.foundation.layout.K0.c(nVar, 0.75f), null, c0814p, 48);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 8, qVar);
        }
    }

    public static final void b(String str, EnumC4175w enumC4175w, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        androidx.compose.ui.q qVar2;
        int i4;
        Function0 function02;
        int i5;
        Function0 function03;
        boolean z;
        boolean z2;
        androidx.compose.ui.q qVar3;
        Function0 function04;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1570119047);
        if ((i & 6) == 0) {
            i3 = i | (c0814p.f(str) ? 4 : 2);
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p.f(enumC4175w) ? 32 : 16;
        }
        int i6 = i2 & 4;
        if (i6 != 0) {
            i4 = i3 | 384;
            qVar2 = qVar;
        } else {
            qVar2 = qVar;
            i4 = i3 | (c0814p.f(qVar2) ? 256 : 128);
        }
        int i7 = i2 & 8;
        if (i7 != 0) {
            i5 = i4 | 3072;
            function02 = function0;
        } else {
            function02 = function0;
            i5 = i4 | (c0814p.h(function02) ? 2048 : 1024);
        }
        if ((i5 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar2;
            function04 = function02;
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVar4 = i6 != 0 ? nVar : qVar2;
            androidx.compose.runtime.V v = C0804k.a;
            if (i7 != 0) {
                c0814p.X(1833169266);
                Object objI = c0814p.I();
                if (objI == v) {
                    objI = new C4392k(5);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                function03 = (Function0) objI;
            } else {
                function03 = function02;
            }
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i8 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar4);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p, bA, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i8))) {
                android.support.v4.media.session.a.z(i8, c0814p, i8, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p, qVarC, c0912h4);
            Object[] objArr = new Object[0];
            c0814p.X(-667204184);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new C4392k(6);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0814p c0814p2 = c0814p;
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI2, c0814p2, 3072, 6);
            int i9 = enumC4175w == null ? -1 : com.quizlet.features.notes.detail.composables.magicnotesdetail.L.a[enumC4175w.ordinal()];
            if (i9 != 1) {
                if (i9 != 2) {
                    c0814p2.X(-667140462);
                    com.quizlet.themes.m.g.p();
                    AbstractC3180j7.a(0, 0, c0814p2, androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.j, 7), "outlineError"));
                    c0814p2.p(false);
                    Unit unit = Unit.a;
                    function03 = function03;
                    z2 = true;
                } else {
                    c0814p2.X(792631675);
                    z2 = true;
                    function03 = function03;
                    androidx.compose.animation.E.f(((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, AbstractC4387f.a, c0814p2, 1572870, 30);
                    androidx.compose.animation.E.f(!((Boolean) interfaceC0773a0.getValue()).booleanValue(), null, null, null, null, androidx.compose.runtime.internal.e.e(-132398687, new com.quizlet.assembly.compose.input.g(interfaceC0773a0, function03, 3), c0814p2), c0814p2, 1572870, 30);
                    c0814p2 = c0814p2;
                    c0814p2.p(false);
                    Unit unit2 = Unit.a;
                }
                c0814p = c0814p2;
            } else {
                c0814p2.X(791632328);
                if (str == null || str.length() == 0) {
                    z = false;
                    z2 = true;
                    c0814p = c0814p2;
                    c0814p.X(791650835);
                    AbstractC3144f7.a(null, c0814p, 0);
                    c0814p.p(false);
                } else {
                    c0814p2.X(791744331);
                    androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
                    int i10 = c0814p2.P;
                    InterfaceC0803j0 interfaceC0803j0L2 = c0814p2.l();
                    androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, nVar);
                    c0814p2.b0();
                    if (c0814p2.O) {
                        c0814p2.k(c0913i);
                    } else {
                        c0814p2.l0();
                    }
                    C0776c.E(c0814p2, kE, c0912h);
                    C0776c.E(c0814p2, interfaceC0803j0L2, c0912h2);
                    if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i10))) {
                        android.support.v4.media.session.a.z(i10, c0814p2, i10, c0912h3);
                    }
                    C0776c.E(c0814p2, qVarC2, c0912h4);
                    androidx.compose.runtime.B b = com.quizlet.themes.g.a;
                    z = false;
                    z2 = true;
                    AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), c0814p2, 0, 1);
                    androidx.compose.runtime.X0 x0 = AndroidCompositionLocals_androidKt.b;
                    AbstractC3673m4.a(new com.quizlet.qatex.c(str, com.quizlet.themes.extensions.a.a((Context) c0814p2.j(x0), R.attr.SysColorTextPrimary), AbstractC3187k5.c((Context) c0814p2.j(x0), R.style.Body_B4), false), AbstractC0460p.f(nVar, ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), androidx.compose.ui.graphics.F.a), true, null, null, c0814p2, 384, 24);
                    c0814p = c0814p2;
                    c0814p.p(true);
                    c0814p.p(false);
                }
                c0814p.p(z);
                Unit unit3 = Unit.a;
            }
            c0814p.p(z2);
            qVar3 = qVar4;
            function04 = function03;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.K(str, enumC4175w, qVar3, function04, i, i2, 0);
        }
    }

    public static final byte[] c(CharsetEncoder charsetEncoder, String input, int i, int i2) {
        Intrinsics.checkNotNullParameter(charsetEncoder, "<this>");
        Intrinsics.checkNotNullParameter(input, "input");
        if (input != null) {
            if (i == 0 && i2 == input.length()) {
                byte[] bytes = input.getBytes(charsetEncoder.charset());
                Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
                return bytes;
            }
            String strSubstring = input.substring(i, i2);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            Intrinsics.e(strSubstring, "null cannot be cast to non-null type java.lang.String");
            byte[] bytes2 = strSubstring.getBytes(charsetEncoder.charset());
            Intrinsics.checkNotNullExpressionValue(bytes2, "getBytes(...)");
            return bytes2;
        }
        ByteBuffer byteBufferEncode = charsetEncoder.encode(CharBuffer.wrap(input, i, i2));
        byte[] bArr = null;
        if (byteBufferEncode.hasArray() && byteBufferEncode.arrayOffset() == 0) {
            byte[] bArrArray = byteBufferEncode.array();
            if (bArrArray.length == byteBufferEncode.remaining()) {
                bArr = bArrArray;
            }
        }
        if (bArr != null) {
            return bArr;
        }
        byte[] bArr2 = new byte[byteBufferEncode.remaining()];
        byteBufferEncode.get(bArr2);
        return bArr2;
    }

    public static final String d(Charset charset) {
        Intrinsics.checkNotNullParameter(charset, "<this>");
        String strName = charset.name();
        Intrinsics.checkNotNullExpressionValue(strName, "name(...)");
        return strName;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void e(androidx.compose.runtime.internal.d r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof androidx.glance.appwidget.N
            if (r0 == 0) goto L13
            r0 = r5
            androidx.glance.appwidget.N r0 = (androidx.glance.appwidget.N) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            androidx.glance.appwidget.N r0 = new androidx.glance.appwidget.N
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r1 = r0.k
            r2 = 1
            if (r1 == 0) goto L34
            if (r1 == r2) goto L2b
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.KotlinNothingValueException r4 = new kotlin.KotlinNothingValueException
            r4.<init>()
            throw r4
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            kotlin.coroutines.CoroutineContext r5 = r0.getContext()
            androidx.glance.appwidget.y r1 = androidx.glance.appwidget.C1221y.a
            kotlin.coroutines.CoroutineContext$Element r5 = r5.get(r1)
            androidx.glance.appwidget.z r5 = (androidx.glance.appwidget.InterfaceC1222z) r5
            if (r5 == 0) goto L4d
            r0.k = r2
            androidx.glance.appwidget.p r5 = (androidx.glance.appwidget.C1188p) r5
            r5.b(r4, r0)
            return
        L4d:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "provideContent requires a ContentReceiver and should only be called from GlanceAppWidget.provideGlance"
            r4.<init>(r5)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.s7.e(androidx.compose.runtime.internal.d, kotlin.coroutines.jvm.internal.c):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x0056, code lost:
    
        if (r10 == r2) goto L35;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0067  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r8v6, types: [com.quizlet.quizletandroid.ui.widgets.b] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object f(com.quizlet.quizletandroid.ui.widgets.y r8, android.content.Context r9, kotlin.coroutines.h r10) {
        /*
            boolean r0 = r10 instanceof androidx.glance.appwidget.O
            r1 = -2147483648(0xffffffff80000000, float:-0.0)
            if (r0 == 0) goto L13
            r0 = r10
            androidx.glance.appwidget.O r0 = (androidx.glance.appwidget.O) r0
            int r2 = r0.n
            r3 = r2 & r1
            if (r3 == 0) goto L13
            int r2 = r2 - r1
            r0.n = r2
            goto L18
        L13:
            androidx.glance.appwidget.O r0 = new androidx.glance.appwidget.O
            r0.<init>(r10)
        L18:
            java.lang.Object r10 = r0.m
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r0.n
            r4 = 1
            r5 = 2
            if (r3 == 0) goto L40
            if (r3 == r4) goto L38
            if (r3 != r5) goto L30
            java.util.Iterator r8 = r0.l
            android.content.Context r9 = r0.k
            com.quizlet.quizletandroid.ui.widgets.b r3 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L61
        L30:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L38:
            android.content.Context r9 = r0.k
            com.quizlet.quizletandroid.ui.widgets.b r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto L59
        L40:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            androidx.glance.appwidget.X r10 = new androidx.glance.appwidget.X
            r10.<init>(r9)
            java.lang.Class r3 = r8.getClass()
            r0.j = r8
            r0.k = r9
            r0.n = r4
            java.io.Serializable r10 = r10.a(r3, r0)
            if (r10 != r2) goto L59
            goto L94
        L59:
            java.lang.Iterable r10 = (java.lang.Iterable) r10
            java.util.Iterator r10 = r10.iterator()
            r3 = r8
            r8 = r10
        L61:
            boolean r10 = r8.hasNext()
            if (r10 == 0) goto L9d
            java.lang.Object r10 = r8.next()
            androidx.glance.appwidget.c r10 = (androidx.glance.appwidget.C1162c) r10
            r0.j = r3
            r0.k = r9
            r0.l = r8
            r0.n = r5
            r3.getClass()
            boolean r6 = r10 instanceof androidx.glance.appwidget.C1162c
            if (r6 == 0) goto L95
            int r10 = r10.a
            r6 = 0
            if (r1 > r10) goto L85
            r7 = -1
            if (r10 >= r7) goto L85
            r6 = r4
        L85:
            if (r6 != 0) goto L95
            java.lang.Object r10 = com.quizlet.quizletandroid.ui.widgets.AbstractC4769b.c(r3, r9, r10, r0)
            kotlin.coroutines.intrinsics.a r6 = kotlin.coroutines.intrinsics.a.a
            if (r10 != r6) goto L90
            goto L92
        L90:
            kotlin.Unit r10 = kotlin.Unit.a
        L92:
            if (r10 != r2) goto L61
        L94:
            return r2
        L95:
            java.lang.IllegalArgumentException r8 = new java.lang.IllegalArgumentException
            java.lang.String r9 = "Invalid Glance ID"
            r8.<init>(r9)
            throw r8
        L9d:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.s7.f(com.quizlet.quizletandroid.ui.widgets.y, android.content.Context, kotlin.coroutines.h):java.lang.Object");
    }
}
