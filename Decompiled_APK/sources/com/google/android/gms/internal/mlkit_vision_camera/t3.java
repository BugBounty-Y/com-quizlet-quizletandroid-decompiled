package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.material3.Q4;
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
import androidx.compose.ui.q;
import androidx.lifecycle.InterfaceC1261w;
import assistantMode.enums.k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_camera.t3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z5;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogData;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.features.folders.composables.C4256l;
import com.quizlet.features.questiontypes.truefalse.l;
import com.quizlet.features.questiontypes.truefalse.n;
import com.quizlet.features.questiontypes.truefalse.o;
import com.quizlet.features.questiontypes.truefalse.p;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.TrueFalseStudiableQuestion;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class t3 {
    public static final void a(com.quizlet.features.questiontypes.truefalse.d dVar, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-322471138);
        int i2 = i | (c0814p.f(dVar) ? 32 : 16) | (c0814p.h(function0) ? 256 : 128) | (c0814p.h(function02) ? 2048 : 1024);
        if ((i2 & 1169) == 1168 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.s();
            float f = com.quizlet.ui.resources.designsystem.generated.j.h;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.w(nVar, DefinitionKt.NO_Float_VALUE, f, 1), "answerLabel");
            com.quizlet.features.questiontypes.data.a aVar = dVar.c;
            Q4.b(AbstractC3106b5.d(c0814p, aVar.a), qVarG, aVar.a(c0814p), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.a)).k, c0814p, 0, 0, 65528);
            c0814p = c0814p;
            mVar.s();
            F2.c(dVar.a, androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), "trueButton"), new com.quizlet.features.infra.models.a(AbstractC3106b5.d(c0814p, R.string.true_button), null, null, false), null, function0, c0814p, ((i2 << 6) & 57344) | 3072, 0);
            mVar.s();
            F2.c(dVar.b, androidx.compose.ui.platform.N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f, 7), "falseButton"), new com.quizlet.features.infra.models.a(AbstractC3106b5.d(c0814p, R.string.false_button), null, null, false), null, function02, c0814p, ((i2 << 3) & 57344) | 3072, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 7, dVar, function0, function02);
        }
    }

    public static final void b(com.quizlet.features.questiontypes.truefalse.m mVar, final com.quizlet.features.questiontypes.truefalse.a aVar, final com.quizlet.features.questiontypes.basequestion.i iVar, final com.quizlet.features.questiontypes.truefalse.b bVar, final Function1 function1, final Function1 function12, final Function0 function0, final Function0 function02, final Function0 function03, final Function0 function04, final androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, final int i, final int i2) {
        int i3;
        int i4;
        C0814p c0814p;
        final com.quizlet.features.questiontypes.truefalse.m mVar2 = mVar;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1173924410);
        if ((i & 6) == 0) {
            i3 = (c0814p2.h(mVar2) ? 4 : 2) | i;
        } else {
            i3 = i;
        }
        if ((i & 48) == 0) {
            i3 |= c0814p2.f(aVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i3 |= (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) == 0 ? c0814p2.f(iVar) : c0814p2.h(iVar) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i3 |= (i & 4096) == 0 ? c0814p2.f(bVar) : c0814p2.h(bVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i3 |= c0814p2.h(function1) ? 16384 : 8192;
        }
        if ((196608 & i) == 0) {
            i3 |= c0814p2.h(function12) ? 131072 : 65536;
        }
        if ((i & 1572864) == 0) {
            i3 |= c0814p2.h(function0) ? 1048576 : 524288;
        }
        if ((i & 12582912) == 0) {
            i3 |= c0814p2.h(function02) ? 8388608 : 4194304;
        }
        if ((i & 100663296) == 0) {
            i3 |= c0814p2.h(function03) ? 67108864 : 33554432;
        }
        if ((i & 805306368) == 0) {
            i3 |= c0814p2.h(function04) ? 536870912 : 268435456;
        }
        if ((i2 & 6) == 0) {
            i4 = i2 | (c0814p2.f(qVar) ? 4 : 2);
        } else {
            i4 = i2;
        }
        int i5 = i3;
        if ((i3 & 306783379) == 306783378 && (i4 & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.X(-736736983);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (objI == v) {
                c0814p2.i0(function02);
                objI = function02;
            }
            Function0 function05 = (Function0) objI;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-736735439, c0814p2, false);
            if (objG == v) {
                objG = C0776c.z(Boolean.FALSE);
                c0814p2.i0(objG);
            }
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) objG;
            c0814p2.p(false);
            com.quizlet.features.questiontypes.basequestion.data.a aVar2 = mVar2.d;
            c0814p2.X(-736732898);
            boolean zH = c0814p2.h(mVar2);
            Object objI2 = c0814p2.I();
            if (zH || objI2 == v) {
                objI2 = new com.quizlet.features.questiontypes.truefalse.ui.e(mVar2, function05, interfaceC0773a0, null);
                c0814p2.i0(objI2);
            }
            c0814p2.p(false);
            C0776c.f(c0814p2, aVar2, (Function2) objI2);
            com.quizlet.assembly.compose.modals.x xVarH = Y5.h(false, false, c0814p2, 48, 5);
            J2.a(function03, function04, c0814p2, (i5 >> 24) & 126);
            K2.a(((com.quizlet.features.questiontypes.truefalse.l) bVar).q, iVar, c0814p2, (i5 >> 3) & ContentType.LONG_FORM_ON_DEMAND);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i6 = c0814p2.P;
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
            C0776c.E(c0814p2, kE, C0914j.f);
            C0776c.E(c0814p2, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p2.O || !Intrinsics.b(c0814p2.I(), Integer.valueOf(i6))) {
                android.support.v4.media.session.a.z(i6, c0814p2, i6, c0912h);
            }
            C0776c.E(c0814p2, qVarC, C0914j.d);
            mVar2 = mVar;
            AbstractC0725t3.a(null, null, androidx.compose.runtime.internal.e.e(-86644143, new com.quizlet.features.folders.composables.F(interfaceC0773a0, function0), c0814p2), null, null, 0, 0L, 0L, null, androidx.compose.runtime.internal.e.e(1812763291, new C4256l(mVar2, aVar, function12, xVarH, function1), c0814p2), c0814p2, 805306752, 507);
            c0814p = c0814p2;
            StudiableImage studiableImage = mVar2.a.b;
            if (studiableImage == null) {
                studiableImage = mVar2.b.b;
            }
            Z5.c(studiableImage != null ? studiableImage.a() : null, null, xVarH, c0814p, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2() { // from class: com.quizlet.features.questiontypes.truefalse.ui.d
                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(i | 1);
                    int iH2 = C0776c.H(i2);
                    com.quizlet.features.questiontypes.truefalse.b bVar2 = bVar;
                    Function0 function06 = function04;
                    q qVar2 = qVar;
                    t3.b(mVar2, aVar, iVar, bVar2, function1, function12, function0, function02, function03, function06, qVar2, (InterfaceC0806l) obj, iH, iH2);
                    return Unit.a;
                }
            };
        }
    }

    public static final void c(com.quizlet.features.questiontypes.truefalse.m mVar, final com.quizlet.features.questiontypes.truefalse.a aVar, Function1 function1, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        com.quizlet.features.questiontypes.truefalse.m mVar2 = mVar;
        Function1 function12 = function1;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1581345440);
        int i2 = i | (c0814p.h(mVar2) ? 32 : 16) | (c0814p.f(aVar) ? 256 : 128) | (c0814p.h(function12) ? 2048 : 1024) | (c0814p.h(function0) ? 16384 : 8192);
        if ((i2 & 9361) == 9360 && c0814p.x()) {
            c0814p.Q();
        } else {
            String strD = AbstractC3106b5.d(c0814p, R.string.definition);
            androidx.compose.runtime.B b = com.quizlet.themes.w.a;
            androidx.compose.ui.text.L l = ((com.quizlet.themes.f) c0814p.j(b)).k;
            androidx.compose.runtime.B b2 = com.quizlet.themes.g.a;
            Q4.b(strD, null, ((com.quizlet.themes.b) c0814p.j(b2)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65530);
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(nVar, "topPrompt");
            com.quizlet.features.questiontypes.data.d dVar = mVar2.a;
            c0814p.X(-1924219726);
            int i3 = i2 & 896;
            boolean z = i3 == 256;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                final int i4 = 1;
                objI = new Function0() { // from class: com.quizlet.features.questiontypes.truefalse.ui.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i4) {
                            case 0:
                                return Boolean.valueOf(aVar.b);
                            default:
                                return Boolean.valueOf(aVar.a);
                        }
                    }
                };
                c0814p.i0(objI);
            }
            Function0 function02 = (Function0) objI;
            c0814p.p(false);
            c0814p.X(-1924217892);
            int i5 = i2 & 7168;
            boolean z2 = i5 == 2048;
            Object objI2 = c0814p.I();
            if (z2 || objI2 == v) {
                objI2 = new com.quizlet.features.practicetest.detail.m(15, function1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            int i6 = (i2 & 57344) | 48;
            L2.a(dVar, qVarG, function02, (Function0) objI2, function0, c0814p, i6);
            Q4.b(AbstractC3106b5.d(c0814p, R.string.term), null, ((com.quizlet.themes.b) c0814p.j(b2)).b.f(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p.j(b)).k, c0814p, 0, 0, 65530);
            c0814p = c0814p;
            androidx.compose.ui.q qVarG2 = androidx.compose.ui.platform.N.G(nVar, "bottomPrompt");
            c0814p.X(-1924204587);
            boolean z3 = i3 == 256;
            Object objI3 = c0814p.I();
            if (z3 || objI3 == v) {
                final int i7 = 0;
                objI3 = new Function0() { // from class: com.quizlet.features.questiontypes.truefalse.ui.b
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i7) {
                            case 0:
                                return Boolean.valueOf(aVar.b);
                            default:
                                return Boolean.valueOf(aVar.a);
                        }
                    }
                };
                c0814p.i0(objI3);
            }
            Function0 function03 = (Function0) objI3;
            c0814p.p(false);
            c0814p.X(-1924202657);
            boolean z4 = i5 == 2048;
            Object objI4 = c0814p.I();
            if (z4 || objI4 == v) {
                function12 = function1;
                objI4 = new com.quizlet.features.practicetest.detail.m(14, function12);
                c0814p.i0(objI4);
            } else {
                function12 = function1;
            }
            c0814p.p(false);
            mVar2 = mVar;
            L2.a(mVar2.b, qVarG2, function03, (Function0) objI4, function0, c0814p, i6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) mVar2, (Object) aVar, (Object) function12, function0, i, 25);
        }
    }

    public static final void d(com.quizlet.features.questiontypes.basequestion.i questionViewModel, androidx.compose.ui.q qVar, com.quizlet.features.questiontypes.truefalse.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        final com.quizlet.features.questiontypes.truefalse.b bVar2;
        com.quizlet.features.questiontypes.truefalse.b bVar3;
        Intrinsics.checkNotNullParameter(questionViewModel, "questionViewModel");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1638567243);
        int i3 = i | (c0814p.f(questionViewModel) ? 4 : 2) | (c0814p.f(qVar) ? 32 : 16) | 128;
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            bVar3 = bVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                c0814p.Y(1890788296);
                androidx.lifecycle.C0 c0A = androidx.lifecycle.viewmodel.compose.a.a(c0814p);
                if (c0A == null) {
                    throw new IllegalStateException("No ViewModelStoreOwner was provided via LocalViewModelStoreOwner");
                }
                dagger.hilt.android.internal.lifecycle.f fVarC = AbstractC3405w1.c(c0A, c0814p);
                c0814p.Y(1729797275);
                Object objE = AbstractC3417z1.e(com.quizlet.features.questiontypes.truefalse.l.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-897);
                bVar2 = (com.quizlet.features.questiontypes.truefalse.b) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
                bVar2 = bVar;
            }
            c0814p.q();
            com.quizlet.features.questiontypes.truefalse.l lVar = (com.quizlet.features.questiontypes.truefalse.l) bVar2;
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(lVar.m, c0814p);
            InterfaceC0773a0 interfaceC0773a0M2 = C0776c.m(lVar.o, c0814p);
            com.quizlet.features.questiontypes.truefalse.m mVar = (com.quizlet.features.questiontypes.truefalse.m) interfaceC0773a0M.getValue();
            com.quizlet.features.questiontypes.truefalse.a aVar = (com.quizlet.features.questiontypes.truefalse.a) interfaceC0773a0M2.getValue();
            c0814p.X(1904857535);
            boolean zH = c0814p.h(bVar2);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zH || objI == v) {
                final int i4 = 0;
                objI = new Function1() { // from class: com.quizlet.features.questiontypes.truefalse.ui.a
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        switch (i4) {
                            case 0:
                                ((l) bVar2).B(new com.quizlet.features.questiontypes.truefalse.q(((Boolean) obj).booleanValue()));
                                break;
                            default:
                                com.quizlet.features.questiontypes.truefalse.c it2 = (com.quizlet.features.questiontypes.truefalse.c) obj;
                                Intrinsics.checkNotNullParameter(it2, "it");
                                ((l) bVar2).B(new p(it2));
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI);
            }
            Function1 function1 = (Function1) objI;
            c0814p.p(false);
            c0814p.X(1904860610);
            boolean zH2 = c0814p.h(bVar2);
            Object objI2 = c0814p.I();
            if (zH2 || objI2 == v) {
                final int i5 = 1;
                objI2 = new Function1() { // from class: com.quizlet.features.questiontypes.truefalse.ui.a
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        switch (i5) {
                            case 0:
                                ((l) bVar2).B(new com.quizlet.features.questiontypes.truefalse.q(((Boolean) obj).booleanValue()));
                                break;
                            default:
                                com.quizlet.features.questiontypes.truefalse.c it2 = (com.quizlet.features.questiontypes.truefalse.c) obj;
                                Intrinsics.checkNotNullParameter(it2, "it");
                                ((l) bVar2).B(new p(it2));
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI2);
            }
            Function1 function12 = (Function1) objI2;
            c0814p.p(false);
            c0814p.X(1904863708);
            boolean zH3 = c0814p.h(bVar2);
            Object objI3 = c0814p.I();
            if (zH3 || objI3 == v) {
                final int i6 = 0;
                objI3 = new Function0() { // from class: com.quizlet.features.questiontypes.truefalse.ui.c
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i6) {
                            case 0:
                                ((l) bVar2).B(o.a);
                                break;
                            case 1:
                                ((l) bVar2).B(n.a);
                                break;
                            case 2:
                                l lVar2 = (l) bVar2;
                                QuestionEventLogData.a.getClass();
                                TrueFalseStudiableQuestion trueFalseStudiableQuestion = lVar2.i;
                                QuestionEventLogData questionEventLogDataA = QuestionEventLogData.Companion.a(trueFalseStudiableQuestion);
                                k kVar = k.e;
                                QuestionEventLogger.DefaultImpls.a(lVar2.d, lVar2.f, "view_start", questionEventLogDataA, 4, null, null, null, trueFalseStudiableQuestion.e, lVar2.h, kVar, 256);
                                break;
                            default:
                                l lVar3 = (l) bVar2;
                                QuestionEventLogData.a.getClass();
                                QuestionEventLogger.DefaultImpls.a(lVar3.d, lVar3.f, "view_end", QuestionEventLogData.Companion.a(lVar3.i), 4, null, null, null, null, null, null, 1920);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI3);
            }
            Function0 function0 = (Function0) objI3;
            c0814p.p(false);
            c0814p.X(1904866554);
            boolean zH4 = c0814p.h(bVar2);
            Object objI4 = c0814p.I();
            if (zH4 || objI4 == v) {
                final int i7 = 1;
                objI4 = new Function0() { // from class: com.quizlet.features.questiontypes.truefalse.ui.c
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i7) {
                            case 0:
                                ((l) bVar2).B(o.a);
                                break;
                            case 1:
                                ((l) bVar2).B(n.a);
                                break;
                            case 2:
                                l lVar2 = (l) bVar2;
                                QuestionEventLogData.a.getClass();
                                TrueFalseStudiableQuestion trueFalseStudiableQuestion = lVar2.i;
                                QuestionEventLogData questionEventLogDataA = QuestionEventLogData.Companion.a(trueFalseStudiableQuestion);
                                k kVar = k.e;
                                QuestionEventLogger.DefaultImpls.a(lVar2.d, lVar2.f, "view_start", questionEventLogDataA, 4, null, null, null, trueFalseStudiableQuestion.e, lVar2.h, kVar, 256);
                                break;
                            default:
                                l lVar3 = (l) bVar2;
                                QuestionEventLogData.a.getClass();
                                QuestionEventLogger.DefaultImpls.a(lVar3.d, lVar3.f, "view_end", QuestionEventLogData.Companion.a(lVar3.i), 4, null, null, null, null, null, null, 1920);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI4);
            }
            Function0 function02 = (Function0) objI4;
            c0814p.p(false);
            c0814p.X(1904869134);
            boolean zH5 = c0814p.h(bVar2);
            Object objI5 = c0814p.I();
            if (zH5 || objI5 == v) {
                final int i8 = 2;
                objI5 = new Function0() { // from class: com.quizlet.features.questiontypes.truefalse.ui.c
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i8) {
                            case 0:
                                ((l) bVar2).B(o.a);
                                break;
                            case 1:
                                ((l) bVar2).B(n.a);
                                break;
                            case 2:
                                l lVar2 = (l) bVar2;
                                QuestionEventLogData.a.getClass();
                                TrueFalseStudiableQuestion trueFalseStudiableQuestion = lVar2.i;
                                QuestionEventLogData questionEventLogDataA = QuestionEventLogData.Companion.a(trueFalseStudiableQuestion);
                                k kVar = k.e;
                                QuestionEventLogger.DefaultImpls.a(lVar2.d, lVar2.f, "view_start", questionEventLogDataA, 4, null, null, null, trueFalseStudiableQuestion.e, lVar2.h, kVar, 256);
                                break;
                            default:
                                l lVar3 = (l) bVar2;
                                QuestionEventLogData.a.getClass();
                                QuestionEventLogger.DefaultImpls.a(lVar3.d, lVar3.f, "view_end", QuestionEventLogData.Companion.a(lVar3.i), 4, null, null, null, null, null, null, 1920);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI5);
            }
            Function0 function03 = (Function0) objI5;
            c0814p.p(false);
            c0814p.X(1904871309);
            boolean zH6 = c0814p.h(bVar2);
            Object objI6 = c0814p.I();
            if (zH6 || objI6 == v) {
                final int i9 = 3;
                objI6 = new Function0() { // from class: com.quizlet.features.questiontypes.truefalse.ui.c
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i9) {
                            case 0:
                                ((l) bVar2).B(o.a);
                                break;
                            case 1:
                                ((l) bVar2).B(n.a);
                                break;
                            case 2:
                                l lVar2 = (l) bVar2;
                                QuestionEventLogData.a.getClass();
                                TrueFalseStudiableQuestion trueFalseStudiableQuestion = lVar2.i;
                                QuestionEventLogData questionEventLogDataA = QuestionEventLogData.Companion.a(trueFalseStudiableQuestion);
                                k kVar = k.e;
                                QuestionEventLogger.DefaultImpls.a(lVar2.d, lVar2.f, "view_start", questionEventLogDataA, 4, null, null, null, trueFalseStudiableQuestion.e, lVar2.h, kVar, 256);
                                break;
                            default:
                                l lVar3 = (l) bVar2;
                                QuestionEventLogData.a.getClass();
                                QuestionEventLogger.DefaultImpls.a(lVar3.d, lVar3.f, "view_end", QuestionEventLogData.Companion.a(lVar3.i), 4, null, null, null, null, null, null, 1920);
                                break;
                        }
                        return Unit.a;
                    }
                };
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            b(mVar, aVar, questionViewModel, bVar2, function1, function12, function0, function02, function03, (Function0) objI6, qVar, c0814p, (i2 << 6) & 896, (i2 >> 3) & 14);
            bVar3 = bVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 8, qVar, (Object) questionViewModel, (Object) bVar3);
        }
    }
}
