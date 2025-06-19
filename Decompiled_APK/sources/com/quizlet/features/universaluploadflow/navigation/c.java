package com.quizlet.features.universaluploadflow.navigation;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import androidx.activity.compose.l;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.glance.layout.t;
import androidx.glance.n;
import androidx.glance.p;
import androidx.navigation.H;
import androidx.navigation.W;
import androidx.navigation.compose.x;
import com.braze.N;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3320b;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.internal.mlkit_vision_common.M3;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.C2;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.navigation.D;
import com.quizlet.features.infra.navigation.q;
import com.quizlet.features.infra.navigation.r;
import com.quizlet.features.universaluploadflow.UniversalUploadFlowActivity;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.z;
import com.quizlet.themes.m;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c {
    public static final void a(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-190652354);
        if (i == 0 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.glance.a aVar = new androidx.glance.a(R.drawable.ic_brand_streak);
            String strD = com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.d(c0814p, R.string.fire_icon_description);
            m mVar = m.g;
            mVar.i();
            float f = com.quizlet.ui.resources.designsystem.generated.h.f;
            mVar.w();
            float f2 = j.f;
            mVar.i();
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            float f3 = 12;
            p pVarF = AbstractC3332e.f(new t(new androidx.glance.unit.c(f + f2)), f + f3);
            mVar.w();
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            p pVarF2 = AbstractC3324c.f(pVarF, f2, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f3, 6);
            c0814p.X(1435654924);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = new z(20);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3189k7.c(aVar, strD, AbstractC3340g.c(pVarF2, (Function1) objI), 0, null, c0814p, 0, 24);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new x(i, 26);
        }
    }

    public static final void b(C2 streakData, p pVar, InterfaceC0806l interfaceC0806l, int i, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(streakData, "streakData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(223186010);
        int i4 = (c0814p.h(streakData) ? 4 : 2) | i;
        int i5 = i2 & 2;
        if (i5 != 0) {
            i3 = i4 | 48;
        } else {
            i3 = i4 | (c0814p.f(pVar) ? 32 : 16);
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            n nVar = n.a;
            if (i5 != 0) {
                pVar = nVar;
            }
            String strValueOf = String.valueOf(streakData.a);
            boolean z = Float.compare(androidx.compose.ui.unit.g.a(((androidx.compose.ui.unit.g) c0814p.j(androidx.glance.j.a)).a), (float) 100) <= 0;
            int i6 = z ? 2 : 1;
            p pVarD = AbstractC3332e.d(nVar);
            m mVar = m.g;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            float f = 12;
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            Intrinsics.checkNotNullParameter(mVar, "<this>");
            AbstractC3320b.a(AbstractC3324c.f(pVarD, f, f, DefinitionKt.NO_Float_VALUE, f, 4).d(pVar), i6, androidx.compose.runtime.internal.e.e(-1054059484, new com.quizlet.quizletandroid.ui.widgets.n(z, streakData, strValueOf), c0814p), c0814p, 3072, 0);
        }
        p pVar2 = pVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(streakData, pVar2, i, i2, 29);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x01ef  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x01f6  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0208  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x020f  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0217  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0232  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x027d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d r34, androidx.compose.runtime.InterfaceC0806l r35, int r36) {
        /*
            Method dump skipped, instructions count: 668
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.universaluploadflow.navigation.c.c(com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.d, androidx.compose.runtime.l, int):void");
    }

    public static final void d(final int i, final int i2, InterfaceC0806l interfaceC0806l, String str, final boolean z) {
        float f;
        final String str2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2036068983);
        int i3 = (c0814p.f(str) ? 4 : 2) | i;
        int i4 = i2 & 2;
        if (i4 != 0) {
            i3 |= 48;
        } else if ((i & 48) == 0) {
            i3 |= c0814p.g(z) ? 32 : 16;
        }
        if ((i3 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            str2 = str;
        } else {
            if (i4 != 0) {
                z = false;
            }
            ((com.quizlet.quizletandroid.ui.widgets.ui.theme.d) c0814p.j(com.quizlet.quizletandroid.ui.widgets.ui.theme.f.a)).getClass();
            androidx.glance.text.g gVarB = com.quizlet.quizletandroid.ui.widgets.ui.theme.d.b(c0814p);
            n nVar = n.a;
            m mVar = m.g;
            if (z) {
                mVar.r();
                f = j.e;
            } else {
                mVar.w();
                f = -j.f;
            }
            str2 = str;
            AbstractC3401v1.a(str2, AbstractC3324c.f(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), gVarB, 0, c0814p, i3 & 14, 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.quizletandroid.ui.widgets.m
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    String str3 = str2;
                    boolean z2 = z;
                    com.quizlet.features.universaluploadflow.navigation.c.d(iH, i2, (InterfaceC0806l) obj, str3, z2);
                    return Unit.a;
                }
            };
        }
    }

    public static final void e(m2 source, H h, e eVar, InterfaceC0806l interfaceC0806l, int i) {
        H hD;
        final e eVar2;
        int i2;
        e eVar3;
        H h2;
        C0814p c0814p;
        e eVar4;
        H h3;
        final int i3 = 0;
        Intrinsics.checkNotNullParameter(source, "source");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-5145177);
        int i4 = i | (c0814p2.f(source) ? 4 : 2) | 144;
        if ((i4 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            h3 = h;
            eVar4 = eVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                hD = O1.d(new W[0], c0814p2);
                c0814p2.X(1907377511);
                Object objB = K6.b(com.quizlet.features.universaluploadflow.di.a.class, c0814p2.j(AndroidCompositionLocals_androidKt.b));
                c0814p2.p(false);
                C4622e c4622e = (C4622e) ((com.quizlet.features.universaluploadflow.di.a) objB);
                eVar2 = new e((D) c4622e.x.get(), (r) c4622e.C.get(), (q) c4622e.z.get(), (com.quizlet.features.infra.navigation.m) c4622e.y.get());
                i2 = i4 & (-1009);
            } else {
                c0814p2.Q();
                i2 = i4 & (-1009);
                hD = h;
                eVar2 = eVar;
            }
            c0814p2.q();
            Activity activity = (Activity) c0814p2.j(l.a);
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            c0814p2.X(2122119550);
            Object objI = c0814p2.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new N(10, activity);
                c0814p2.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            Object objG = Z.g(2122122773, c0814p2, false);
            if (objG == v) {
                objG = new com.quizlet.features.setpage.header.ui.g(7, eVar2, function0);
                c0814p2.i0(objG);
            }
            Function1 function1 = (Function1) objG;
            Object objG2 = Z.g(2122130432, c0814p2, false);
            if (objG2 == v) {
                objG2 = new com.quizlet.features.questionnaire.screens.c(16, eVar2, function0);
                c0814p2.i0(objG2);
            }
            Function0 function02 = (Function0) objG2;
            c0814p2.p(false);
            int i5 = UniversalUploadFlowActivity.h;
            final Intent intentA = M3.a(context, source);
            c0814p2.X(2122144380);
            boolean zH = c0814p2.h(eVar2) | c0814p2.h(intentA);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v) {
                objI2 = new Function0() { // from class: com.quizlet.features.universaluploadflow.navigation.a
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i3) {
                            case 0:
                                eVar2.j(intentA);
                                break;
                            default:
                                eVar2.r(intentA);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objI2);
            }
            Function0 function03 = (Function0) objI2;
            c0814p2.p(false);
            c0814p2.X(2122147741);
            boolean zH2 = c0814p2.h(eVar2) | c0814p2.h(intentA);
            Object objI3 = c0814p2.I();
            if (zH2 || objI3 == v) {
                objI3 = new Function0() { // from class: com.quizlet.features.universaluploadflow.navigation.a
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i) {
                            case 0:
                                eVar2.j(intentA);
                                break;
                            default:
                                eVar2.r(intentA);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p2.i0(objI3);
            }
            Function0 function04 = (Function0) objI3;
            c0814p2.p(false);
            c0814p2.X(2122155782);
            int i6 = ((i2 & 14) != 4 ? 0 : 1) | (c0814p2.h(eVar2) ? 1 : 0) | (c0814p2.h(hD) ? 1 : 0) | (c0814p2.f(function03) ? 1 : 0) | (c0814p2.f(function04) ? 1 : 0);
            Object objI4 = c0814p2.I();
            if (i6 != 0 || objI4 == v) {
                e eVar5 = eVar2;
                com.quizlet.features.blocks.ui.b bVar = new com.quizlet.features.blocks.ui.b(source, function0, eVar5, hD, function1, function02, function03, function04, 2);
                eVar3 = eVar5;
                h2 = hD;
                c0814p2.i0(bVar);
                objI4 = bVar;
            } else {
                h2 = hD;
                eVar3 = eVar2;
            }
            c0814p2.p(false);
            c0814p = c0814p2;
            Q1.d(h2, "upload_flow", null, (Function1) objI4, c0814p, 48, 12);
            eVar4 = eVar3;
            h3 = h2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 21, source, h3, eVar4);
        }
    }
}
