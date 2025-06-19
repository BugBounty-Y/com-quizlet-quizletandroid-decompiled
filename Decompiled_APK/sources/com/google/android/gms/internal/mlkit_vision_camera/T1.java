package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.camera.camera2.internal.C0132i;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes2.dex */
public abstract class T1 {
    public static final void a(String primaryButtonText, String secondaryButtonText, Function0 onPrimaryButtonClick, Function0 onSecondaryButtonClick, androidx.compose.ui.n nVar, int i, androidx.compose.ui.graphics.painter.b bVar, boolean z, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        androidx.compose.ui.graphics.painter.b bVar2;
        int i4;
        boolean z2;
        int i5;
        int i6;
        int i7;
        boolean z3;
        androidx.compose.ui.n nVar2;
        androidx.compose.ui.graphics.painter.b bVar3;
        androidx.compose.ui.graphics.painter.b bVar4;
        androidx.compose.ui.n nVar3;
        int i8;
        boolean z4;
        Intrinsics.checkNotNullParameter(primaryButtonText, "primaryButtonText");
        Intrinsics.checkNotNullParameter(secondaryButtonText, "secondaryButtonText");
        Intrinsics.checkNotNullParameter(onPrimaryButtonClick, "onPrimaryButtonClick");
        Intrinsics.checkNotNullParameter(onSecondaryButtonClick, "onSecondaryButtonClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2133781431);
        int i9 = i2 | (c0814p.f(primaryButtonText) ? 4 : 2) | (c0814p.f(secondaryButtonText) ? 32 : 16) | (c0814p.h(onPrimaryButtonClick) ? 256 : 128) | (c0814p.h(onSecondaryButtonClick) ? 2048 : 1024);
        int i10 = 90112 | i9;
        int i11 = i3 & 64;
        if (i11 != 0) {
            i4 = i9 | 1662976;
            bVar2 = bVar;
        } else {
            bVar2 = bVar;
            i4 = i10 | (c0814p.h(bVar2) ? 1048576 : 524288);
        }
        int i12 = 128 & i3;
        if (i12 != 0) {
            i5 = i4 | 12582912;
            z2 = z;
        } else {
            z2 = z;
            i5 = i4 | (c0814p.g(z2) ? 8388608 : 4194304);
        }
        if ((4793491 & i5) == 4793490 && c0814p.x()) {
            c0814p.Q();
            nVar3 = nVar;
            i8 = i;
            bVar4 = bVar2;
            z4 = z2;
        } else {
            c0814p.S();
            int i13 = i2 & 1;
            androidx.compose.ui.n nVar4 = androidx.compose.ui.n.b;
            if (i13 == 0 || c0814p.w()) {
                androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p);
                int i14 = i5 & (-458753);
                if (i11 != 0) {
                    bVar2 = null;
                }
                i6 = i14;
                i7 = bVarG.a;
                z3 = i12 != 0 ? true : z2;
                nVar2 = nVar4;
                bVar3 = bVar2;
            } else {
                c0814p.Q();
                nVar2 = nVar;
                i7 = i;
                i6 = i5 & (-458753);
                bVar3 = bVar2;
                z3 = z2;
            }
            c0814p.q();
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            if (i7 == 0) {
                c0814p.X(189632678);
                androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(nVar2, 1.0f);
                androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
                int i15 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
                androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, qVarC);
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
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i15))) {
                    android.support.v4.media.session.a.z(i15, c0814p, i15, c0912h);
                }
                C0776c.E(c0814p, qVarC2, C0914j.d);
                c0814p.X(859122192);
                if (z3) {
                    int i16 = i6 >> 3;
                    d(secondaryButtonText, bVar3, onSecondaryButtonClick, null, c0814p, (i16 & 14) | ((i6 >> 15) & ContentType.LONG_FORM_ON_DEMAND) | (i16 & 896), 8);
                }
                c0814p.p(false);
                com.quizlet.themes.m.g.s();
                AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.d(nVar4, com.quizlet.ui.resources.designsystem.generated.j.h));
                b((i6 & 14) | ((i6 >> 3) & ContentType.LONG_FORM_ON_DEMAND), 4, c0814p, null, primaryButtonText, onPrimaryButtonClick);
                c0814p.p(true);
                c0814p.p(false);
            } else {
                c0814p.X(190187206);
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                androidx.compose.ui.q qVarQ = androidx.compose.foundation.layout.K0.q(nVar2, DefinitionKt.NO_Float_VALUE, com.quizlet.themes.m.U0, 1);
                androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.e, androidx.compose.ui.b.k, c0814p, 54);
                int i17 = c0814p.P;
                InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
                androidx.compose.ui.q qVarC3 = androidx.compose.ui.a.c(c0814p, qVarQ);
                InterfaceC0915k.D0.getClass();
                C0913i c0913i2 = C0914j.b;
                c0814p.b0();
                if (c0814p.O) {
                    c0814p.k(c0913i2);
                } else {
                    c0814p.l0();
                }
                C0776c.E(c0814p, g0B, C0914j.f);
                C0776c.E(c0814p, interfaceC0803j0L2, C0914j.e);
                C0912h c0912h2 = C0914j.g;
                if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i17))) {
                    android.support.v4.media.session.a.z(i17, c0814p, i17, c0912h2);
                }
                C0776c.E(c0814p, qVarC3, C0914j.d);
                androidx.compose.foundation.layout.I0 i0 = androidx.compose.foundation.layout.I0.a;
                c0814p.X(859145766);
                if (z3) {
                    int i18 = i6 >> 3;
                    androidx.compose.ui.graphics.painter.b bVar5 = bVar3;
                    d(secondaryButtonText, bVar5, onSecondaryButtonClick, i0.a(nVar4, 0.5f, true), c0814p, (i18 & 14) | ((i6 >> 15) & ContentType.LONG_FORM_ON_DEMAND) | (i18 & 896), 0);
                    bVar3 = bVar5;
                    c0814p = c0814p;
                }
                c0814p.p(false);
                mVar.s();
                AbstractC0382e.f(c0814p, androidx.compose.foundation.layout.K0.o(nVar4, com.quizlet.ui.resources.designsystem.generated.j.h));
                b((i6 & 14) | ((i6 >> 3) & ContentType.LONG_FORM_ON_DEMAND), 0, c0814p, i0.a(nVar4, 0.5f, true), primaryButtonText, onPrimaryButtonClick);
                c0814p.p(true);
                c0814p.p(false);
            }
            bVar4 = bVar3;
            nVar3 = nVar2;
            i8 = i7;
            z4 = z3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.modals.o(primaryButtonText, secondaryButtonText, onPrimaryButtonClick, onSecondaryButtonClick, nVar3, i8, bVar4, z4, i2, i3);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:43:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(int r18, int r19, androidx.compose.runtime.InterfaceC0806l r20, androidx.compose.ui.q r21, java.lang.String r22, kotlin.jvm.functions.Function0 r23) {
        /*
            r4 = r18
            r15 = r20
            androidx.compose.runtime.p r15 = (androidx.compose.runtime.C0814p) r15
            r0 = -667237530(0xffffffffd83ac366, float:-8.213936E14)
            r15.Z(r0)
            r0 = r4 & 6
            r1 = r22
            if (r0 != 0) goto L1d
            boolean r0 = r15.f(r1)
            if (r0 == 0) goto L1a
            r0 = 4
            goto L1b
        L1a:
            r0 = 2
        L1b:
            r0 = r0 | r4
            goto L1e
        L1d:
            r0 = r4
        L1e:
            r2 = r4 & 48
            if (r2 != 0) goto L31
            r2 = r23
            boolean r3 = r15.h(r2)
            if (r3 == 0) goto L2d
            r3 = 32
            goto L2f
        L2d:
            r3 = 16
        L2f:
            r0 = r0 | r3
            goto L33
        L31:
            r2 = r23
        L33:
            r3 = r19 & 4
            if (r3 == 0) goto L3c
            r0 = r0 | 384(0x180, float:5.38E-43)
        L39:
            r5 = r21
            goto L4e
        L3c:
            r5 = r4 & 384(0x180, float:5.38E-43)
            if (r5 != 0) goto L39
            r5 = r21
            boolean r6 = r15.f(r5)
            if (r6 == 0) goto L4b
            r6 = 256(0x100, float:3.59E-43)
            goto L4d
        L4b:
            r6 = 128(0x80, float:1.8E-43)
        L4d:
            r0 = r0 | r6
        L4e:
            r6 = r0 & 147(0x93, float:2.06E-43)
            r7 = 146(0x92, float:2.05E-43)
            if (r6 != r7) goto L60
            boolean r6 = r15.x()
            if (r6 != 0) goto L5b
            goto L60
        L5b:
            r15.Q()
            r3 = r5
            goto L82
        L60:
            if (r3 == 0) goto L65
            androidx.compose.ui.n r3 = androidx.compose.ui.n.b
            goto L66
        L65:
            r3 = r5
        L66:
            r5 = 1065353216(0x3f800000, float:1.0)
            androidx.compose.ui.q r6 = androidx.compose.foundation.layout.K0.c(r3, r5)
            r5 = r0 & 14
            int r0 = r0 << 3
            r0 = r0 & 896(0x380, float:1.256E-42)
            r16 = r5 | r0
            r13 = 0
            r14 = 0
            r8 = 0
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r17 = 1016(0x3f8, float:1.424E-42)
            r5 = r1
            r7 = r2
            com.google.android.gms.internal.mlkit_vision_document_scanner.W4.a(r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17)
        L82:
            androidx.compose.runtime.o0 r7 = r15.r()
            if (r7 == 0) goto L96
            com.quizlet.assembly.compose.buttons.f0 r0 = new com.quizlet.assembly.compose.buttons.f0
            r6 = 2
            r5 = r19
            r1 = r22
            r2 = r23
            r0.<init>(r1, r2, r3, r4, r5, r6)
            r7.d = r0
        L96:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.T1.b(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String, kotlin.jvm.functions.Function0):void");
    }

    public static final kotlinx.serialization.internal.h0 c(String serialName, kotlinx.serialization.descriptors.f kind) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(kind, "kind");
        if (StringsKt.O(serialName)) {
            throw new IllegalArgumentException("Blank serial names are prohibited");
        }
        kotlin.collections.builders.h hVar = kotlinx.serialization.internal.i0.a;
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(kind, "kind");
        kotlinx.serialization.internal.i0.a(serialName);
        return new kotlinx.serialization.internal.h0(serialName, kind);
    }

    /* JADX WARN: Removed duplicated region for block: B:42:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00a8  */
    /* JADX WARN: Removed duplicated region for block: B:50:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(java.lang.String r25, androidx.compose.ui.graphics.painter.b r26, kotlin.jvm.functions.Function0 r27, androidx.compose.ui.q r28, androidx.compose.runtime.InterfaceC0806l r29, int r30, int r31) {
        /*
            r5 = r30
            r0 = r29
            androidx.compose.runtime.p r0 = (androidx.compose.runtime.C0814p) r0
            r1 = -1805644871(0xffffffff94600bb9, float:-1.1311422E-26)
            r0.Z(r1)
            r1 = r5 & 6
            if (r1 != 0) goto L1d
            r1 = r25
            boolean r2 = r0.f(r1)
            if (r2 == 0) goto L1a
            r2 = 4
            goto L1b
        L1a:
            r2 = 2
        L1b:
            r2 = r2 | r5
            goto L20
        L1d:
            r1 = r25
            r2 = r5
        L20:
            r3 = r5 & 48
            if (r3 != 0) goto L33
            r3 = r26
            boolean r4 = r0.h(r3)
            if (r4 == 0) goto L2f
            r4 = 32
            goto L31
        L2f:
            r4 = 16
        L31:
            r2 = r2 | r4
            goto L35
        L33:
            r3 = r26
        L35:
            r4 = r5 & 384(0x180, float:5.38E-43)
            r8 = r27
            if (r4 != 0) goto L47
            boolean r4 = r0.h(r8)
            if (r4 == 0) goto L44
            r4 = 256(0x100, float:3.59E-43)
            goto L46
        L44:
            r4 = 128(0x80, float:1.8E-43)
        L46:
            r2 = r2 | r4
        L47:
            r4 = r31 & 8
            if (r4 == 0) goto L50
            r2 = r2 | 3072(0xc00, float:4.305E-42)
        L4d:
            r6 = r28
            goto L62
        L50:
            r6 = r5 & 3072(0xc00, float:4.305E-42)
            if (r6 != 0) goto L4d
            r6 = r28
            boolean r7 = r0.f(r6)
            if (r7 == 0) goto L5f
            r7 = 2048(0x800, float:2.87E-42)
            goto L61
        L5f:
            r7 = 1024(0x400, float:1.435E-42)
        L61:
            r2 = r2 | r7
        L62:
            r7 = r2 & 1171(0x493, float:1.641E-42)
            r9 = 1170(0x492, float:1.64E-42)
            if (r7 != r9) goto L76
            boolean r7 = r0.x()
            if (r7 != 0) goto L6f
            goto L76
        L6f:
            r0.Q()
            r21 = r0
            r4 = r6
            goto La2
        L76:
            if (r4 == 0) goto L7b
            androidx.compose.ui.n r4 = androidx.compose.ui.n.b
            goto L7c
        L7b:
            r4 = r6
        L7c:
            r6 = 1065353216(0x3f800000, float:1.0)
            androidx.compose.ui.q r7 = androidx.compose.foundation.layout.K0.c(r4, r6)
            r6 = r2 & 910(0x38e, float:1.275E-42)
            int r2 = r2 >> 3
            r23 = r2 & 14
            r19 = 0
            r20 = 0
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r13 = 0
            r15 = 0
            r17 = 0
            r24 = 7160(0x1bf8, float:1.0033E-41)
            r21 = r0
            r18 = r3
            r22 = r6
            r6 = r1
            com.google.android.gms.internal.mlkit_vision_document_scanner.Y4.a(r6, r7, r8, r9, r10, r11, r12, r13, r15, r17, r18, r19, r20, r21, r22, r23, r24)
        La2:
            androidx.compose.runtime.o0 r7 = r21.r()
            if (r7 == 0) goto Lb7
            androidx.navigation.compose.F r0 = new androidx.navigation.compose.F
            r1 = r25
            r2 = r26
            r3 = r27
            r6 = r31
            r0.<init>(r1, r2, r3, r4, r5, r6)
            r7.d = r0
        Lb7:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.T1.d(java.lang.String, androidx.compose.ui.graphics.painter.b, kotlin.jvm.functions.Function0, androidx.compose.ui.q, androidx.compose.runtime.l, int, int):void");
    }

    public static androidx.concurrent.futures.l e(kotlinx.coroutines.I i) {
        Intrinsics.checkNotNullParameter(i, "<this>");
        androidx.concurrent.futures.l lVarB = Y5.b(new C0132i(i, 21));
        Intrinsics.checkNotNullExpressionValue(lVarB, "getFuture { completer ->…      }\n        tag\n    }");
        return lVarB;
    }

    public static final kotlinx.serialization.descriptors.g f(String serialName, SerialDescriptor[] typeParameters, Function1 builderAction) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(typeParameters, "typeParameters");
        Intrinsics.checkNotNullParameter(builderAction, "builderAction");
        if (StringsKt.O(serialName)) {
            throw new IllegalArgumentException("Blank serial names are prohibited");
        }
        kotlinx.serialization.descriptors.a aVar = new kotlinx.serialization.descriptors.a(serialName);
        builderAction.invoke(aVar);
        return new kotlinx.serialization.descriptors.g(serialName, kotlinx.serialization.descriptors.j.b, aVar.c.size(), C4933y.P(typeParameters), aVar);
    }

    public static final kotlinx.serialization.descriptors.g g(String serialName, U1 kind, SerialDescriptor[] typeParameters, Function1 builder) {
        Intrinsics.checkNotNullParameter(serialName, "serialName");
        Intrinsics.checkNotNullParameter(kind, "kind");
        Intrinsics.checkNotNullParameter(typeParameters, "typeParameters");
        Intrinsics.checkNotNullParameter(builder, "builder");
        if (StringsKt.O(serialName)) {
            throw new IllegalArgumentException("Blank serial names are prohibited");
        }
        if (kind.equals(kotlinx.serialization.descriptors.j.b)) {
            throw new IllegalArgumentException("For StructureKind.CLASS please use 'buildClassSerialDescriptor' instead");
        }
        kotlinx.serialization.descriptors.a aVar = new kotlinx.serialization.descriptors.a(serialName);
        builder.invoke(aVar);
        return new kotlinx.serialization.descriptors.g(serialName, kind, aVar.c.size(), C4933y.P(typeParameters), aVar);
    }
}
