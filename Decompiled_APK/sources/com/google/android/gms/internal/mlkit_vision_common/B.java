package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0238e;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B {
    public static volatile boolean a = true;

    public static final void a(int i, com.quizlet.features.setpage.studypreview.g gVar, C0466e c0466e, kotlinx.collections.immutable.e eVar, androidx.compose.runtime.snapshots.q qVar, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0466e c0466e2;
        kotlinx.collections.immutable.e eVar2;
        androidx.compose.runtime.snapshots.q qVar2;
        C0238e c0238e;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1034656691);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.d(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= (i2 & 64) == 0 ? c0814p.f(gVar) : c0814p.h(gVar) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            c0466e2 = c0466e;
            i3 |= c0814p.f(c0466e2) ? 256 : 128;
        } else {
            c0466e2 = c0466e;
        }
        if ((i2 & 3072) == 0) {
            eVar2 = eVar;
            i3 |= c0814p.h(eVar2) ? 2048 : 1024;
        } else {
            eVar2 = eVar;
        }
        if ((i2 & 24576) == 0) {
            qVar2 = qVar;
            i3 |= c0814p.f(qVar2) ? 16384 : 8192;
        } else {
            qVar2 = qVar;
        }
        if ((196608 & i2) == 0) {
            i3 |= c0814p.f(nVar) ? 131072 : 65536;
        }
        if ((74899 & i3) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            Configuration configuration = (Configuration) c0814p.j(AndroidCompositionLocals_androidKt.a);
            float f = configuration.screenWidthDp;
            float f2 = configuration.screenHeightDp;
            androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
            float fC0 = bVar.c0(f);
            float f3 = -bVar.c0(f2);
            c0814p.X(-1084597204);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            if (objI == obj) {
                objI = AbstractC0240f.a(f3);
                c0814p.i0(objI);
            }
            C0238e c0238e2 = (C0238e) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-1084594965, c0814p, false);
            if (objG == obj) {
                objG = AbstractC0240f.a(fC0);
                c0814p.i0(objG);
            }
            C0238e c0238e3 = (C0238e) objG;
            Object objG2 = com.google.android.gms.measurement.internal.Z.g(-1084592928, c0814p, false);
            if (objG2 == obj) {
                objG2 = AbstractC0240f.a(DefinitionKt.NO_Float_VALUE);
                c0814p.i0(objG2);
            }
            C0238e c0238e4 = (C0238e) objG2;
            c0814p.p(false);
            Unit unit = Unit.a;
            c0814p.X(-1084590345);
            boolean zH = ((i3 & 57344) == 16384) | c0814p.h(c0238e2) | c0814p.h(c0238e3) | c0814p.h(c0238e4);
            Object objI2 = c0814p.I();
            if (zH || objI2 == obj) {
                c0238e = c0238e4;
                Object dVar = new com.quizlet.features.setpage.studypreview.ui.d(c0238e2, c0238e3, qVar2, c0238e, null);
                c0814p.i0(dVar);
                objI2 = dVar;
            } else {
                c0238e = c0238e4;
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            b(i, gVar, c0466e2, eVar2, qVar, nVar, ((Number) c0238e2.d()).floatValue(), ((Number) c0238e3.d()).floatValue(), ((Number) c0238e.d()).floatValue(), c0814p, i3 & 524286, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.F(i, gVar, c0466e, eVar, qVar, i2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:102:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00c4  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x00e0  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x00fc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(final int r17, final com.quizlet.features.setpage.studypreview.g r18, final androidx.compose.foundation.pager.C0466e r19, final kotlinx.collections.immutable.e r20, final androidx.compose.runtime.snapshots.q r21, final androidx.compose.ui.q r22, float r23, float r24, float r25, androidx.compose.runtime.InterfaceC0806l r26, final int r27, final int r28) {
        /*
            Method dump skipped, instructions count: 323
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.B.b(int, com.quizlet.features.setpage.studypreview.g, androidx.compose.foundation.pager.e, kotlinx.collections.immutable.e, androidx.compose.runtime.snapshots.q, androidx.compose.ui.q, float, float, float, androidx.compose.runtime.l, int, int):void");
    }

    public static final void c(int i, com.quizlet.features.setpage.studypreview.g viewModel, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i2) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-520858094);
        int i3 = (c0814p2.d(i) ? 4 : 2) | i2 | (c0814p2.f(viewModel) ? 32 : 16) | 384;
        if ((i3 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(viewModel.i, c0814p2);
            com.quizlet.features.setpage.studypreview.data.e eVar = (com.quizlet.features.setpage.studypreview.data.e) interfaceC0773a0M.getValue();
            if (eVar instanceof com.quizlet.features.setpage.studypreview.data.c) {
                nVar2 = nVar3;
                c0814p = c0814p2;
            } else {
                if (!(eVar instanceof com.quizlet.features.setpage.studypreview.data.d)) {
                    throw new NoWhenBranchMatchedException();
                }
                c0814p2.X(1500848213);
                Object objI = c0814p2.I();
                Object obj = C0804k.a;
                if (objI == obj) {
                    com.quizlet.features.setpage.studypreview.data.e eVar2 = (com.quizlet.features.setpage.studypreview.data.e) interfaceC0773a0M.getValue();
                    Intrinsics.e(eVar2, "null cannot be cast to non-null type com.quizlet.features.setpage.studypreview.data.StudyPreviewListState.Populated");
                    objI = ((com.quizlet.features.setpage.studypreview.data.d) eVar2).a;
                    c0814p2.i0(objI);
                }
                List<com.quizlet.features.setpage.studypreview.data.a> list = (List) objI;
                c0814p2.p(false);
                c0814p2.X(1500851970);
                boolean zH = c0814p2.h(list);
                Object objI2 = c0814p2.I();
                if (zH || objI2 == obj) {
                    objI2 = new com.braze.managers.U(list, 5);
                    c0814p2.i0(objI2);
                }
                c0814p2.p(false);
                C0466e c0466eB = androidx.compose.foundation.pager.I.b(0, (Function0) objI2, c0814p2, 0, 3);
                c0814p2.X(1500853614);
                Object objI3 = c0814p2.I();
                Object obj2 = objI3;
                if (objI3 == obj) {
                    androidx.compose.runtime.snapshots.q qVar = new androidx.compose.runtime.snapshots.q();
                    ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                    for (com.quizlet.features.setpage.studypreview.data.a aVar : list) {
                        arrayList.add(com.quizlet.assembly.compose.components.flashcards.a.d);
                    }
                    qVar.addAll(arrayList);
                    c0814p2.i0(qVar);
                    obj2 = qVar;
                }
                androidx.compose.runtime.snapshots.q qVar2 = (androidx.compose.runtime.snapshots.q) obj2;
                c0814p2.p(false);
                c0814p2.X(1500860280);
                boolean zF = c0814p2.f(c0466eB);
                int i4 = i3 & ContentType.LONG_FORM_ON_DEMAND;
                boolean z = (i4 == 32) | zF;
                Object objI4 = c0814p2.I();
                if (z || objI4 == obj) {
                    objI4 = new com.quizlet.features.setpage.studypreview.ui.i(c0466eB, viewModel, null);
                    c0814p2.i0(objI4);
                }
                c0814p2.p(false);
                C0776c.f(c0814p2, c0466eB, (Function2) objI4);
                if (((Boolean) C0776c.m(viewModel.k, c0814p2).getValue()).booleanValue()) {
                    c0814p2.X(-717439614);
                    a(i, viewModel, c0466eB, AbstractC3409x1.k(list), qVar2, c0814p2, 196608 | (i3 & 14) | 24576 | i4);
                    c0814p2.p(false);
                    nVar2 = nVar3;
                    c0814p = c0814p2;
                } else {
                    c0814p2.X(-717067800);
                    b(i, viewModel, c0466eB, AbstractC3409x1.k(list), qVar2, nVar3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, c0814p2, (i3 & 14) | 24576 | i4 | 196608, 448);
                    nVar2 = nVar3;
                    C0814p c0814p3 = c0814p2;
                    c0814p3.p(false);
                    c0814p = c0814p3;
                }
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.progress.a(i, viewModel, nVar2, i2);
        }
    }

    public static Drawable d(Context context, Context context2, int i, Resources.Theme theme) {
        try {
            if (a) {
                return e(context2, i, theme);
            }
        } catch (Resources.NotFoundException unused) {
        } catch (IllegalStateException e) {
            if (context.getPackageName().equals(context2.getPackageName())) {
                throw e;
            }
            return context2.getDrawable(i);
        } catch (NoClassDefFoundError unused2) {
            a = false;
        }
        if (theme == null) {
            theme = context2.getTheme();
        }
        Resources resources = context2.getResources();
        ThreadLocal threadLocal = androidx.core.content.res.k.a;
        return resources.getDrawable(i, theme);
    }

    public static Drawable e(Context context, int i, Resources.Theme theme) {
        if (theme != null) {
            androidx.appcompat.view.d dVar = new androidx.appcompat.view.d(context);
            dVar.b = theme;
            dVar.a(theme.getResources().getConfiguration());
            context = dVar;
        }
        return com.facebook.appevents.g.f(context, i);
    }
}
