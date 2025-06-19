package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import assistantMode.types.C1454a;
import assistantMode.types.unions.AudioAttribute;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.C5160h;
import org.wordpress.aztec.spans.C5161i;

/* loaded from: classes2.dex */
public abstract class M2 {
    public static final void a(androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1319348050);
        if ((((c0814p.f(qVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            long j = ((com.quizlet.themes.b) c0814p.j(b)).C0;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVar, j, androidx.compose.foundation.shape.e.a(f));
            mVar.u();
            float f2 = com.quizlet.ui.resources.designsystem.generated.j.g;
            mVar.s();
            androidx.compose.ui.q qVarV = AbstractC0382e.v(qVarF, f, f2);
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, 0);
            int i2 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarV);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i2))) {
                android.support.v4.media.session.a.z(i2, c0814p, i2, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            Q4.b(AbstractC3106b5.d(c0814p, R.string.try_again_label), null, ((com.quizlet.themes.b) c0814p.j(b)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).l, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.cards.d(i, 12, qVar);
        }
    }

    public static final AudioAttribute b(C1454a card) {
        Intrinsics.checkNotNullParameter(card, "card");
        assistantMode.enums.m mVar = assistantMode.enums.m.c;
        String strB = card.b(mVar);
        if (strB == null) {
            strB = card.j(mVar);
        }
        String strB2 = card.b(mVar);
        if (strB2 == null) {
            strB2 = card.k(mVar);
        }
        if (strB == null || strB2 == null) {
            return null;
        }
        return new AudioAttribute(strB, strB2);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterative(DepthRegionTraversal.java:31)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visit(SwitchOverStringVisitor.java:60)
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0072  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final org.wordpress.aztec.spans.C5160h c(int r2, java.lang.String r3, org.wordpress.aztec.C5146b r4, org.wordpress.aztec.EnumC5145a r5, org.wordpress.aztec.formatting.c r6) {
        /*
            java.lang.String r0 = "tag"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            java.lang.String r0 = "attributes"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            java.lang.String r0 = "alignmentRendering"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            java.lang.String r0 = "headerStyle"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.util.Locale r0 = java.util.Locale.getDefault()
            java.lang.String r1 = "getDefault(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)
            java.lang.String r3 = r3.toLowerCase(r0)
            java.lang.String r0 = "toLowerCase(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r0)
            int r0 = r3.hashCode()
            switch(r0) {
                case 3273: goto L6a;
                case 3274: goto L5e;
                case 3275: goto L52;
                case 3276: goto L46;
                case 3277: goto L3a;
                case 3278: goto L2e;
                default: goto L2d;
            }
        L2d:
            goto L72
        L2e:
            java.lang.String r0 = "h6"
            boolean r3 = r3.equals(r0)
            if (r3 != 0) goto L37
            goto L72
        L37:
            org.wordpress.aztec.x r3 = org.wordpress.aztec.x.g
            goto L77
        L3a:
            java.lang.String r0 = "h5"
            boolean r3 = r3.equals(r0)
            if (r3 != 0) goto L43
            goto L72
        L43:
            org.wordpress.aztec.x r3 = org.wordpress.aztec.x.f
            goto L77
        L46:
            java.lang.String r0 = "h4"
            boolean r3 = r3.equals(r0)
            if (r3 != 0) goto L4f
            goto L72
        L4f:
            org.wordpress.aztec.x r3 = org.wordpress.aztec.x.e
            goto L77
        L52:
            java.lang.String r0 = "h3"
            boolean r3 = r3.equals(r0)
            if (r3 != 0) goto L5b
            goto L72
        L5b:
            org.wordpress.aztec.x r3 = org.wordpress.aztec.x.d
            goto L77
        L5e:
            java.lang.String r0 = "h2"
            boolean r3 = r3.equals(r0)
            if (r3 != 0) goto L67
            goto L72
        L67:
            org.wordpress.aztec.x r3 = org.wordpress.aztec.x.c
            goto L77
        L6a:
            java.lang.String r0 = "h1"
            boolean r3 = r3.equals(r0)
            if (r3 != 0) goto L75
        L72:
            org.wordpress.aztec.x r3 = org.wordpress.aztec.x.b
            goto L77
        L75:
            org.wordpress.aztec.x r3 = org.wordpress.aztec.x.b
        L77:
            org.wordpress.aztec.spans.h r2 = d(r2, r3, r4, r5, r6)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.M2.c(int, java.lang.String, org.wordpress.aztec.b, org.wordpress.aztec.a, org.wordpress.aztec.formatting.c):org.wordpress.aztec.spans.h");
    }

    public static final C5160h d(int i, org.wordpress.aztec.G textFormat, C5146b attributes, EnumC5145a alignmentRendering, org.wordpress.aztec.formatting.c headerStyle) {
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(headerStyle, "headerStyle");
        int iOrdinal = alignmentRendering.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                return new C5160h(i, textFormat, attributes, headerStyle);
            }
            throw new NoWhenBranchMatchedException();
        }
        Intrinsics.checkNotNullParameter(textFormat, "textFormat");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(headerStyle, "headerStyle");
        C5161i c5161i = new C5161i(i, textFormat, attributes, headerStyle);
        c5161i.k = i;
        c5161i.l = attributes;
        c5161i.m = headerStyle;
        c5161i.n = null;
        return c5161i;
    }

    public static final AudioAttribute e(C1454a card) {
        Intrinsics.checkNotNullParameter(card, "card");
        assistantMode.enums.m mVar = assistantMode.enums.m.b;
        String strB = card.b(mVar);
        if (strB == null) {
            strB = card.j(mVar);
        }
        String strB2 = card.b(mVar);
        if (strB2 == null) {
            strB2 = card.k(mVar);
        }
        if (strB == null || strB2 == null) {
            return null;
        }
        return new AudioAttribute(strB, strB2);
    }
}
