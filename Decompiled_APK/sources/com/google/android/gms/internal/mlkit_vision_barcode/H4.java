package com.google.android.gms.internal.mlkit_vision_barcode;

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
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class H4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-42002716);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            mVar.s();
            mVar.s();
            androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar, f, DefinitionKt.NO_Float_VALUE, f, f, 2);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarY);
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
            float f2 = com.quizlet.themes.m.r0;
            com.google.android.gms.internal.mlkit_vision_document_scanner.E5.b(f2, androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.o(nVar, SubsamplingScaleImageView.ORIENTATION_180), "LoadingShimmerHeader"), null, c0814p, 48, 4);
            androidx.compose.ui.q qVarO = androidx.compose.foundation.layout.K0.o(nVar, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED);
            mVar.q();
            com.google.android.gms.internal.mlkit_vision_document_scanner.E5.b(f2, androidx.compose.ui.platform.N.G(AbstractC0382e.y(qVarO, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "LoadingShimmerHeader"), null, c0814p, 0, 4);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.x(i, 9);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0033  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:31:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(int r16, int r17, androidx.compose.runtime.InterfaceC0806l r18, androidx.compose.ui.n r19, kotlin.jvm.functions.Function0 r20) {
        /*
            r12 = r18
            androidx.compose.runtime.p r12 = (androidx.compose.runtime.C0814p) r12
            r0 = 201490682(0xc0280fa, float:1.0053648E-31)
            r12.Z(r0)
            r0 = r16 | 6
            r1 = r17 & 2
            if (r1 == 0) goto L15
            r0 = r16 | 54
        L12:
            r2 = r20
            goto L27
        L15:
            r2 = r16 & 48
            if (r2 != 0) goto L12
            r2 = r20
            boolean r3 = r12.h(r2)
            if (r3 == 0) goto L24
            r3 = 32
            goto L26
        L24:
            r3 = 16
        L26:
            r0 = r0 | r3
        L27:
            r3 = r0 & 19
            r4 = 18
            if (r3 != r4) goto L33
            boolean r3 = r12.x()
            if (r3 != 0) goto L35
        L33:
            r3 = r0
            goto L3d
        L35:
            r12.Q()
            r3 = r2
            r2 = r19
            goto Lb6
        L3d:
            androidx.compose.ui.n r0 = androidx.compose.ui.n.b
            r4 = 0
            if (r1 == 0) goto L61
            r1 = -1068222045(0xffffffffc05439a3, float:-3.3160179)
            r12.X(r1)
            java.lang.Object r1 = r12.I()
            androidx.compose.runtime.V r2 = androidx.compose.runtime.C0804k.a
            if (r1 != r2) goto L5a
            com.quizlet.features.emailconfirmation.ui.composables.c r1 = new com.quizlet.features.emailconfirmation.ui.composables.c
            r2 = 10
            r1.<init>(r2)
            r12.i0(r1)
        L5a:
            kotlin.jvm.functions.Function0 r1 = (kotlin.jvm.functions.Function0) r1
            r12.p(r4)
            r15 = r1
            goto L62
        L61:
            r15 = r2
        L62:
            androidx.compose.runtime.B r1 = com.quizlet.themes.g.a
            java.lang.Object r1 = r12.j(r1)
            com.quizlet.themes.b r1 = (com.quizlet.themes.b) r1
            com.quizlet.ui.resources.designsystem.generated.p r1 = r1.b
            long r6 = r1.g()
            r1 = 360309978(0x1579e4da, float:5.0465682E-26)
            r12.X(r1)
            java.util.WeakHashMap r1 = androidx.compose.foundation.layout.S0.w
            androidx.compose.foundation.layout.S0 r1 = androidx.compose.foundation.layout.C0380d.e(r12)
            androidx.compose.foundation.layout.S0 r2 = androidx.compose.foundation.layout.C0380d.e(r12)
            androidx.compose.foundation.layout.v0 r5 = new androidx.compose.foundation.layout.v0
            androidx.compose.foundation.layout.M0 r2 = r2.k
            int r8 = androidx.compose.foundation.layout.AbstractC0382e.g
            r5.<init>(r2, r8)
            androidx.compose.foundation.layout.a r10 = new androidx.compose.foundation.layout.a
            androidx.compose.foundation.layout.c r1 = r1.g
            r10.<init>(r1, r5)
            r12.p(r4)
            com.quizlet.explanations.questiondetail.ui.composables.m r1 = new com.quizlet.explanations.questiondetail.ui.composables.m
            r2 = 4
            r1.<init>(r2, r15)
            r2 = -145737290(0xfffffffff75039b6, float:-4.2233135E33)
            androidx.compose.runtime.internal.d r1 = androidx.compose.runtime.internal.e.e(r2, r1, r12)
            androidx.compose.runtime.internal.d r11 = com.quizlet.features.folders.composables.AbstractC4247c.c
            r2 = r3 & 14
            r3 = 805306416(0x30000030, float:4.6566395E-10)
            r13 = r2 | r3
            r5 = 0
            r8 = 0
            r2 = 0
            r3 = 0
            r4 = 0
            r14 = 188(0xbc, float:2.63E-43)
            androidx.compose.material3.AbstractC0725t3.a(r0, r1, r2, r3, r4, r5, r6, r8, r10, r11, r12, r13, r14)
            r2 = r0
            r3 = r15
        Lb6:
            androidx.compose.runtime.o0 r0 = r12.r()
            if (r0 == 0) goto Lc8
            com.quizlet.features.achievements.ui.composables.n r1 = new com.quizlet.features.achievements.ui.composables.n
            r6 = 1
            r4 = r16
            r5 = r17
            r1.<init>(r2, r3, r4, r5, r6)
            r0.d = r1
        Lc8:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.H4.b(int, int, androidx.compose.runtime.l, androidx.compose.ui.n, kotlin.jvm.functions.Function0):void");
    }

    public static final Object[] c(Object[] objArr, int i, Object obj, Object obj2) {
        Object[] objArr2 = new Object[objArr.length + 2];
        C4930v.j(objArr, 0, objArr2, i, 6);
        C4930v.h(objArr, i + 2, objArr2, i, objArr.length);
        objArr2[i] = obj;
        objArr2[i + 1] = obj2;
        return objArr2;
    }

    public static final Object[] d(int i, Object[] objArr) {
        Object[] objArr2 = new Object[objArr.length - 2];
        C4930v.j(objArr, 0, objArr2, i, 6);
        C4930v.h(objArr, i, objArr2, i + 2, objArr.length);
        return objArr2;
    }

    public static final Object[] e(int i, Object[] objArr) {
        Object[] objArr2 = new Object[objArr.length - 1];
        C4930v.j(objArr, 0, objArr2, i, 6);
        C4930v.h(objArr, i, objArr2, i + 1, objArr.length);
        return objArr2;
    }

    public static final int f(int i, int i2) {
        return (i >> i2) & 31;
    }
}
