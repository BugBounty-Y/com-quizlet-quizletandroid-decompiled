package com.google.mlkit.common.model;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0392j;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.foundation.layout.K0;
import androidx.compose.foundation.layout.S0;
import androidx.compose.foundation.lazy.A;
import androidx.compose.foundation.lazy.D;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.foundation.pager.I;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.runtime.W0;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.q;
import androidx.lifecycle.compose.d;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.ContentType;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3137f0;
import com.google.android.gms.internal.mlkit_vision_barcode.C5;
import com.google.android.gms.internal.mlkit_vision_barcode.D5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.features.achievements.ui.composables.n;
import com.quizlet.features.achievements.ui.composables.p;
import com.quizlet.features.flashcards.C4236j;
import com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.r;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.C4390i;
import com.quizlet.features.subjects.model.e;
import com.quizlet.generated.enums.K1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.x;
import com.quizlet.quizletandroid.ui.subject.f;
import com.quizlet.quizletandroid.ui.subject.viewmodel.g;
import com.quizlet.quizletandroid.ui.subject.viewmodel.h;
import com.quizlet.themes.m;
import com.quizlet.themes.w;
import com.quizlet.ui.compose.C4815h;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.WeakHashMap;
import kotlin.InterfaceC4938g;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class a {
    public static final void a(A a, int i, Function2 function2, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1772308443);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.f(a) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.d(i) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.h(function2) ? 256 : 128;
        }
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            c0814p.X(1113313480);
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = C0776c.q(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(a, 7));
                c0814p.i0(objI);
            }
            c0814p.p(false);
            function2.invoke(Integer.valueOf(((Number) ((W0) objI).getValue()).intValue()), Integer.valueOf(i));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new n(a, i, function2, i2, 5);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0094  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void b(com.quizlet.quizletandroid.ui.subject.viewmodel.h r13, kotlin.jvm.functions.Function0 r14, kotlin.jvm.functions.Function0 r15, androidx.compose.ui.n r16, androidx.compose.runtime.InterfaceC0806l r17, int r18) {
        /*
            Method dump skipped, instructions count: 219
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.mlkit.common.model.a.b(com.quizlet.quizletandroid.ui.subject.viewmodel.h, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, androidx.compose.ui.n, androidx.compose.runtime.l, int):void");
    }

    public static final void c(g gVar, Function2 function2, Function1 function1, Function1 function12, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        int i2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1788527980);
        int i3 = i | (c0814p.h(gVar) ? 4 : 2) | (c0814p.h(function2) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | 24576;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            kotlinx.collections.immutable.b<K1> bVar = gVar.b;
            c0814p.X(62838134);
            ArrayList arrayList = new ArrayList(C.q(bVar, 10));
            for (K1 k1 : bVar) {
                Intrinsics.checkNotNullParameter(k1, "<this>");
                switch (e.b[k1.ordinal()]) {
                    case 1:
                        i2 = R.string.explanation_subject_history;
                        break;
                    case 2:
                        i2 = R.string.explanation_subject_linguistics;
                        break;
                    case 3:
                        i2 = R.string.explanation_subject_literature;
                        break;
                    case 4:
                        i2 = R.string.explanation_subject_art_history;
                        break;
                    case 5:
                        i2 = R.string.explanation_subject_dance;
                        break;
                    case 6:
                        i2 = R.string.explanation_subject_vocabulary;
                        break;
                    case 7:
                        i2 = R.string.explanation_subject_visual_arts;
                        break;
                    case 8:
                        i2 = R.string.explanation_subject_literature_and_english;
                        break;
                    case 9:
                        i2 = R.string.explanation_subject_theater;
                        break;
                    case 10:
                        i2 = R.string.explanation_subject_philosophy;
                        break;
                    case 11:
                        i2 = R.string.explanation_subject_film_and_tv;
                        break;
                    case 12:
                        i2 = R.string.explanation_subject_music;
                        break;
                    case 13:
                        i2 = R.string.explanation_subject_arts_and_humanities;
                        break;
                    case 14:
                        i2 = R.string.explanation_subject_english;
                        break;
                    case 15:
                        i2 = R.string.explanation_subject_spanish;
                        break;
                    case 16:
                        i2 = R.string.explanation_subject_german;
                        break;
                    case 17:
                        i2 = R.string.explanation_subject_french;
                        break;
                    case 18:
                        i2 = R.string.explanation_subject_chinese;
                        break;
                    case 19:
                        i2 = R.string.explanation_subject_korean;
                        break;
                    case 20:
                        i2 = R.string.explanation_subject_japanese;
                        break;
                    case 21:
                        i2 = R.string.explanation_subject_latin;
                        break;
                    case EventType.WINDOW_STATE /* 22 */:
                        i2 = R.string.explanation_subject_other_languages;
                        break;
                    case EventType.AUDIO /* 23 */:
                        i2 = R.string.explanation_subject_math;
                        break;
                    case EventType.VIDEO /* 24 */:
                        i2 = R.string.explanation_subject_arithmetic;
                        break;
                    case EventType.SUBS /* 25 */:
                        i2 = R.string.explanation_subject_geometry;
                        break;
                    case EventType.CDN /* 26 */:
                        i2 = R.string.explanation_subject_math_notation;
                        break;
                    case 27:
                        i2 = R.string.explanation_subject_algebra;
                        break;
                    case 28:
                        i2 = R.string.explanation_subject_discrete_math;
                        break;
                    case 29:
                        i2 = R.string.explanation_subject_math_foundations;
                        break;
                    case 30:
                        i2 = R.string.explanation_subject_probability;
                        break;
                    case 31:
                        i2 = R.string.explanation_subject_statistics;
                        break;
                    case 32:
                        i2 = R.string.explanation_subject_applied_math;
                        break;
                    case 33:
                        i2 = R.string.explanation_subject_calculus;
                        break;
                    case 34:
                        i2 = R.string.explanation_subject_physics;
                        break;
                    case 35:
                        i2 = R.string.explanation_subject_biology;
                        break;
                    case 36:
                        i2 = R.string.explanation_subject_earth_science;
                        break;
                    case 37:
                        i2 = R.string.explanation_subject_chemistry;
                        break;
                    case 38:
                        i2 = R.string.explanation_subject_space_science;
                        break;
                    case 39:
                        i2 = R.string.explanation_subject_computer_science;
                        break;
                    case RequestError.NETWORK_FAILURE /* 40 */:
                        i2 = R.string.explanation_subject_medicine;
                        break;
                    case RequestError.NO_DEV_KEY /* 41 */:
                        i2 = R.string.explanation_subject_engineering;
                        break;
                    case 42:
                        i2 = R.string.explanation_subject_world_geography;
                        break;
                    case 43:
                        i2 = R.string.explanation_subject_law;
                        break;
                    case 44:
                        i2 = R.string.explanation_subject_anthropology;
                        break;
                    case 45:
                        i2 = R.string.explanation_subject_business;
                        break;
                    case 46:
                        i2 = R.string.explanation_subject_sociology;
                        break;
                    case 47:
                        i2 = R.string.explanation_subject_geography;
                        break;
                    case 48:
                        i2 = R.string.explanation_subject_economics;
                        break;
                    case 49:
                        i2 = R.string.explanation_subject_psychology;
                        break;
                    case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                        i2 = R.string.explanation_subject_human_geography;
                        break;
                    default:
                        throw new NoWhenBranchMatchedException();
                }
                arrayList.add(new C4815h(AbstractC3106b5.d(c0814p, i2), null, androidx.compose.runtime.internal.e.e(-2001757479, new x(gVar, function2, function1, 2), c0814p)));
            }
            c0814p.p(false);
            c0814p.X(62849611);
            boolean zF = c0814p.f(bVar);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (zF || objI == v) {
                objI = new C4390i(bVar, 1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            C0466e c0466eB = I.b(gVar.c, (Function0) objI, c0814p, 0, 2);
            String strD = AbstractC3106b5.d(c0814p, gVar.a);
            kotlinx.collections.immutable.e eVarK = AbstractC3409x1.k(arrayList);
            c0814p.X(62855828);
            boolean zH = ((i3 & 7168) == 2048) | c0814p.h(gVar) | c0814p.f(bVar);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                objI2 = new d(gVar, function12, bVar, 24);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            e(strD, c0466eB, eVarK, (Function1) objI2, nVar3, c0814p, 25088);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new r(gVar, function2, function1, function12, nVar2, i, 22);
        }
    }

    public static final void d(h state, Function0 onBackClick, Function0 onSearchSetClick, Function0 onCreateSetClick, Function2 updateScrollPercentage, Function1 onSubjectClick, Function1 onSetClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(onBackClick, "onBackClick");
        Intrinsics.checkNotNullParameter(onSearchSetClick, "onSearchSetClick");
        Intrinsics.checkNotNullParameter(onCreateSetClick, "onCreateSetClick");
        Intrinsics.checkNotNullParameter(updateScrollPercentage, "updateScrollPercentage");
        Intrinsics.checkNotNullParameter(onSubjectClick, "onSubjectClick");
        Intrinsics.checkNotNullParameter(onSetClick, "onSetClick");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1331280526);
        if (((i | (c0814p2.f(state) ? 4 : 2) | (c0814p2.h(onBackClick) ? 32 : 16) | (c0814p2.h(onSearchSetClick) ? 256 : 128) | (c0814p2.h(onCreateSetClick) ? 2048 : 1024) | (c0814p2.h(updateScrollPercentage) ? 16384 : 8192) | (c0814p2.h(onSubjectClick) ? 131072 : 65536) | (c0814p2.h(onSetClick) ? 1048576 : 524288) | 12582912) & 4793491) == 4793490 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            androidx.compose.runtime.internal.d dVarE = androidx.compose.runtime.internal.e.e(197683246, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.d(5, onBackClick), c0814p2);
            androidx.compose.runtime.internal.d dVarE2 = androidx.compose.runtime.internal.e.e(1908334093, new x(state, onSearchSetClick, onCreateSetClick, 3), c0814p2);
            androidx.compose.runtime.internal.d dVarE3 = androidx.compose.runtime.internal.e.e(-163062781, new com.quizlet.assembly.compose.menu.g((Object) state, (Object) updateScrollPercentage, (InterfaceC4938g) onSetClick, (Object) onSubjectClick, 16), c0814p2);
            c0814p = c0814p2;
            nVar2 = nVar3;
            AbstractC0725t3.a(nVar2, dVarE, dVarE2, null, null, 0, 0L, 0L, c0374a, dVarE3, c0814p, 805306806, 248);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4236j(state, onBackClick, onSearchSetClick, onCreateSetClick, updateScrollPercentage, onSubjectClick, onSetClick, nVar2, i);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void e(String str, C0466e c0466e, kotlinx.collections.immutable.e eVar, Function1 function1, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1661074460);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(str) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(c0466e) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p.f(eVar) : c0814p.h(eVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(function1) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.f(qVar) ? 16384 : 8192;
        }
        int i3 = i2;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            C0380d c0380d = AbstractC0398m.a;
            m mVar = m.g;
            mVar.s();
            float f = j.h;
            C0392j c0392jG = AbstractC0398m.g(f);
            q qVarG = qVar.g(K0.c);
            mVar.s();
            q qVarW = AbstractC0382e.w(qVarG, f, DefinitionKt.NO_Float_VALUE, 2);
            B bA = androidx.compose.foundation.layout.A.a(c0392jG, androidx.compose.ui.b.m, c0814p, 0);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            q qVarC = androidx.compose.ui.a.c(c0814p, qVarW);
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
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.m();
            f(str, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.n, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), c0814p, i3 & 14);
            int i5 = i3 & ContentType.LONG_FORM_ON_DEMAND;
            int i6 = ((i3 >> 6) & 14) | 8 | i5;
            C5.b(eVar, c0466e, null, c0814p, i6, 4);
            c0814p.X(-865990405);
            boolean z2 = (i5 == 32) | ((i3 & 7168) == 2048);
            Object objI = c0814p.I();
            if (z2 || objI == C0804k.a) {
                z = false;
                objI = new f(0 == true ? 1 : 0, c0466e, function1);
                c0814p.i0(objI);
            } else {
                z = false;
            }
            c0814p.p(z);
            D5.a(eVar, c0466e, null, 0L, false, (Function1) objI, c0814p, i6, 28);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new p(str, c0466e, eVar, function1, qVar, i);
        }
    }

    public static final void f(String title, q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        Intrinsics.checkNotNullParameter(title, "title");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(518253340);
        if ((i & 6) == 0) {
            i2 = i | (c0814p2.f(title) ? 4 : 2);
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.f(qVar) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            Q4.b(title, qVar, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(w.a)).d, c0814p, i2 & 126, 0, 65532);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.m(title, qVar, i, 7);
        }
    }

    public static final void g(g gVar, Function2 function2, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1333654920);
        int i2 = i | (c0814p.h(gVar) ? 4 : 2) | (c0814p.h(function2) ? 32 : 16) | (c0814p.h(function1) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            A a = D.a(0, c0814p, 3);
            a(a, gVar.d.size(), function2, c0814p, (i2 << 3) & 896);
            C0380d c0380d = AbstractC0398m.a;
            m mVar = m.g;
            mVar.s();
            C0392j c0392jG = AbstractC0398m.g(j.h);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            mVar.u();
            q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, j.g, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
            c0814p.X(601324033);
            boolean zH = ((i2 & 896) == 256) | c0814p.h(gVar);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.quizlet.features.setpage.header.ui.g(29, gVar, function1);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            AbstractC3137f0.a(qVarY, a, null, c0392jG, null, null, false, (Function1) objI, c0814p, 0, 236);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.startpage.nav2.composables.f(i, 10, gVar, function2, function1);
        }
    }

    public static final void h(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.n nVar, Function0 function0) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2038664037);
        int i2 = (c0814p.h(function0) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar2 = androidx.compose.ui.n.b;
            com.quizlet.themes.e.a(c0814p).a.getClass();
            AbstractC3691o6.c(nVar2, null, 0L, 0L, com.quizlet.ui.resources.icons.d.m(c0814p), function0, null, null, c0814p, 6 | ((i2 << 15) & 458752), OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_SERVICE_SPECIFIC_OFF);
            nVar = nVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.A(function0, nVar, i, 5);
        }
    }
}
