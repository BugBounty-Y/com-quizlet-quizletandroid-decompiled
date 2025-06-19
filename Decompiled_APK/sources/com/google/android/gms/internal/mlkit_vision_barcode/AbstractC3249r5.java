package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.material3.AbstractC0666j3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.r5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3249r5 {
    public static final void a(androidx.compose.ui.q qVar, long j, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(633305855);
        int i4 = i2 & 1;
        if (i4 != 0) {
            i3 = i | 6;
        } else if ((i & 6) == 0) {
            i3 = (c0814p.f(qVar) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= ((i2 & 2) == 0 && c0814p.e(j)) ? 32 : 16;
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                if (i4 != 0) {
                    qVar = androidx.compose.ui.n.b;
                }
                if ((i2 & 2) != 0) {
                    j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.h();
                }
            } else {
                c0814p.Q();
            }
            c0814p.q();
            androidx.compose.ui.i iVar = androidx.compose.ui.b.e;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0460p.f(qVar.g(androidx.compose.foundation.layout.K0.c), j, androidx.compose.ui.graphics.F.a), "loading_full_screen");
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(iVar, false);
            int i5 = c0814p.P;
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
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i5))) {
                android.support.v4.media.session.a.z(i5, c0814p, i5, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            AbstractC0666j3.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).K(), DefinitionKt.NO_Float_VALUE, 0L, 0, c0814p, 0, 29);
            c0814p.p(true);
        }
        final androidx.compose.ui.q qVar2 = qVar;
        final long j2 = j;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.ui.compose.m
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    long j3 = j2;
                    AbstractC3249r5.a(qVar2, j3, (InterfaceC0806l) obj, iH, i2);
                    return Unit.a;
                }
            };
        }
    }

    public static com.quizlet.features.infra.basestudy.data.models.x b(androidx.lifecycle.m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Object objA = savedStateHandle.a("studyableModelData");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyableModelData studyableModelData = (StudyableModelData) objA;
        Object objA2 = savedStateHandle.a("studyableModelLocalId");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        long jLongValue = ((Number) objA2).longValue();
        Object objA3 = savedStateHandle.a("selectedOnlyIntent");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        boolean zBooleanValue = ((Boolean) objA3).booleanValue();
        Object objA4 = savedStateHandle.a("screen_name_key");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        String str = (String) objA4;
        Object objA5 = savedStateHandle.a("navigationSource");
        if (objA5 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int iIntValue = ((Number) objA5).intValue();
        long[] jArr = (long[]) savedStateHandle.a("termsToShowIntent");
        ArrayList arrayList = jArr != null ? new ArrayList(C4933y.O(jArr)) : null;
        com.quizlet.generated.enums.z1 z1Var = com.quizlet.generated.enums.A1.Companion;
        Object objA6 = savedStateHandle.a("study_mode_type_key");
        if (objA6 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int iIntValue2 = ((Number) objA6).intValue();
        z1Var.getClass();
        return new com.quizlet.features.infra.basestudy.data.models.x(studyableModelData, jLongValue, zBooleanValue, str, iIntValue, arrayList, com.quizlet.generated.enums.z1.a(iIntValue2), (Boolean) savedStateHandle.a("startsInSrsMode"));
    }

    public static final int c(androidx.compose.ui.text.font.u uVar, int i) {
        boolean z = uVar.compareTo(androidx.compose.ui.text.font.u.d) >= 0;
        boolean z2 = i == 1;
        if (z2 && z) {
            return 3;
        }
        if (z) {
            return 1;
        }
        return z2 ? 2 : 0;
    }
}
