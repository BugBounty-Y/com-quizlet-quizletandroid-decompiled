package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
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
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.data.model.C4112b1;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;

/* loaded from: classes2.dex */
public abstract class X1 {
    public static final void a(com.quizlet.features.practicetest.common.data.a questionDetail, int i, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i2) {
        C0814p c0814p;
        boolean z;
        Intrinsics.checkNotNullParameter(questionDetail, "questionDetail");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1908202188);
        if ((((c0814p2.h(questionDetail) ? 4 : 2) | i2 | (c0814p2.d(i) ? 32 : 16) | (c0814p2.f(qVar) ? 256 : 128)) & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p2, 0);
            int i3 = c0814p2.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p2.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p2, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p2.b0();
            if (c0814p2.O) {
                c0814p2.k(c0913i);
            } else {
                c0814p2.l0();
            }
            C0912h c0912h = C0914j.f;
            C0776c.E(c0814p2, g0B, c0912h);
            C0912h c0912h2 = C0914j.e;
            C0776c.E(c0814p2, interfaceC0803j0L, c0912h2);
            C0912h c0912h3 = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p2, i3, c0912h3);
            }
            C0912h c0912h4 = C0914j.d;
            C0776c.E(c0814p2, qVarC, c0912h4);
            String strC = AbstractC3106b5.c(R.string.practice_test_detail_question_number, new Object[]{Integer.valueOf(i)}, c0814p2);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            Q4.b(strC, null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(b)).o, c0814p2, 0, 0, 65534);
            c0814p = c0814p2;
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L2 = c0814p.l();
            androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p, layoutWeightElement);
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, c0912h);
            C0776c.E(c0814p, interfaceC0803j0L2, c0912h2);
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
            }
            C0776c.E(c0814p, qVarC2, c0912h4);
            if (questionDetail.b) {
                c0814p.X(-1779745812);
                b(questionDetail.a, c0814p, 0);
                c0814p.p(false);
                z = true;
            } else {
                c0814p.X(-1779668746);
                Q4.b(AbstractC3106b5.d(c0814p, R.string.practice_test_unsupported_question), null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).o, c0814p, 0, 0, 65530);
                c0814p = c0814p;
                c0814p.p(false);
                z = true;
            }
            c0814p.p(z);
            c0814p.p(z);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(questionDetail, i, qVar, i2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r12v2 */
    /* JADX WARN: Type inference failed for: r12v3, types: [int] */
    /* JADX WARN: Type inference failed for: r12v7 */
    /* JADX WARN: Type inference failed for: r21v4 */
    /* JADX WARN: Type inference failed for: r2v8, types: [java.lang.Object, java.util.List] */
    public static final void b(com.quizlet.data.model.X0 x0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1225697978);
        if ((((c0814p.h(x0) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).o;
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.u();
            androidx.compose.ui.n nVar3 = nVar2;
            boolean z = true;
            Q4.b(x0.b, AbstractC0382e.y(nVar2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.g, 7), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65532);
            c0814p = c0814p;
            ArrayList arrayList = x0.f;
            com.quizlet.data.model.R0 r0 = arrayList != null ? (com.quizlet.data.model.R0) CollectionsKt.firstOrNull(arrayList) : null;
            c0814p.X(-1244682944);
            ?? r12 = 0;
            if (r0 != null) {
                O1.a(r0, null, c0814p, 0);
                Unit unit = Unit.a;
            }
            c0814p.p(false);
            List list = x0.d;
            if (!list.isEmpty()) {
                int i2 = 0;
                for (Object obj : list) {
                    int i3 = i2 + 1;
                    if (i2 < 0) {
                        kotlin.collections.B.p();
                        throw null;
                    }
                    C4112b1 c4112b1 = (C4112b1) obj;
                    androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.j, c0814p, r12);
                    int i4 = c0814p.P;
                    InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
                    androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, nVar3);
                    InterfaceC0915k.D0.getClass();
                    C0913i c0913i = C0914j.b;
                    c0814p.b0();
                    if (c0814p.O) {
                        c0814p.k(c0913i);
                    } else {
                        c0814p.l0();
                    }
                    C0912h c0912h = C0914j.f;
                    C0776c.E(c0814p, g0B, c0912h);
                    C0912h c0912h2 = C0914j.e;
                    C0776c.E(c0814p, interfaceC0803j0L, c0912h2);
                    C0912h c0912h3 = C0914j.g;
                    if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                        android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h3);
                    }
                    C0912h c0912h4 = C0914j.d;
                    C0776c.E(c0814p, qVarC, c0912h4);
                    String strD = AbstractC3106b5.d(c0814p, R.string.practice_test_detail_answer_option_bullet_point);
                    androidx.compose.runtime.B b = com.quizlet.themes.w.a;
                    androidx.compose.ui.text.L l2 = ((com.quizlet.themes.f) c0814p.j(b)).o;
                    com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                    mVar.s();
                    float f = com.quizlet.ui.resources.designsystem.generated.j.h;
                    androidx.compose.ui.n nVar4 = nVar3;
                    androidx.compose.ui.q qVarY = AbstractC0382e.y(nVar4, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                    List list2 = list;
                    boolean z2 = r12;
                    int i5 = i2;
                    C0814p c0814p2 = c0814p;
                    Q4.b(strD, qVarY, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l2, c0814p2, 0, 0, 65532);
                    if (1.0f <= 0.0d) {
                        throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
                    }
                    LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, z);
                    androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(AbstractC0398m.c, androidx.compose.ui.b.m, c0814p2, z2 ? 1 : 0);
                    int i6 = c0814p2.P;
                    InterfaceC0803j0 interfaceC0803j0L2 = c0814p2.l();
                    androidx.compose.ui.q qVarC2 = androidx.compose.ui.a.c(c0814p2, layoutWeightElement);
                    c0814p2.b0();
                    if (c0814p2.O) {
                        c0814p2.k(c0913i);
                    } else {
                        c0814p2.l0();
                    }
                    C0776c.E(c0814p2, bA, c0912h);
                    C0776c.E(c0814p2, interfaceC0803j0L2, c0912h2);
                    if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i6))) {
                        android.support.v4.media.session.a.z(i6, c0814p2, i6, c0912h3);
                    }
                    C0776c.E(c0814p2, qVarC2, c0912h4);
                    String str = c4112b1.a;
                    androidx.compose.ui.text.L l3 = ((com.quizlet.themes.f) c0814p2.j(b)).o;
                    mVar.s();
                    Q4.b(str, AbstractC0382e.y(nVar4, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l3, c0814p2, 0, 0, 65532);
                    c0814p = c0814p2;
                    ?? r2 = c4112b1.b;
                    com.quizlet.data.model.R0 r02 = r2 != 0 ? (com.quizlet.data.model.R0) CollectionsKt.firstOrNull(r2) : null;
                    c0814p.X(-686879683);
                    if (r02 != null) {
                        O1.a(r02, null, c0814p, z2 ? 1 : 0);
                        Unit unit2 = Unit.a;
                    }
                    c0814p.p(z2);
                    c0814p.p(true);
                    c0814p.p(true);
                    c0814p.X(-1244649977);
                    if (i5 == kotlin.collections.B.i(list2)) {
                        mVar.s();
                        nVar = nVar4;
                        AbstractC0382e.f(c0814p, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7));
                    } else {
                        nVar = nVar4;
                    }
                    c0814p.p(z2);
                    r12 = z2 ? 1 : 0;
                    z = true;
                    nVar3 = nVar;
                    i2 = i3;
                    list = list2;
                }
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(x0, i, 15);
        }
    }

    public static final void c(Encoder encoder) {
        Intrinsics.checkNotNullParameter(encoder, "<this>");
        if ((encoder instanceof kotlinx.serialization.json.o ? (kotlinx.serialization.json.o) encoder : null) != null) {
            return;
        }
        throw new IllegalStateException("This serializer can be used only with Json format.Expected Encoder to be JsonEncoder, got " + kotlin.jvm.internal.K.a(encoder.getClass()));
    }

    public static final kotlinx.serialization.json.j d(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "<this>");
        kotlinx.serialization.json.j jVar = decoder instanceof kotlinx.serialization.json.j ? (kotlinx.serialization.json.j) decoder : null;
        if (jVar != null) {
            return jVar;
        }
        throw new IllegalStateException("This serializer can be used only with Json format.Expected Decoder to be JsonDecoder, got " + kotlin.jvm.internal.K.a(decoder.getClass()));
    }

    public static final void e(HashMap map, Function1 fetchBlock) {
        int i;
        Intrinsics.checkNotNullParameter(map, "map");
        Intrinsics.checkNotNullParameter(fetchBlock, "fetchBlock");
        HashMap map2 = new HashMap(999);
        loop0: while (true) {
            i = 0;
            for (Object key : map.keySet()) {
                Intrinsics.checkNotNullExpressionValue(key, "key");
                map2.put(key, map.get(key));
                i++;
                if (i == 999) {
                    break;
                }
            }
            fetchBlock.invoke(map2);
            map2.clear();
        }
        if (i > 0) {
            fetchBlock.invoke(map2);
        }
    }
}
