package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.pager.C0466e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.quizlet.assembly.compose.buttons.C4097w;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.library.AbstractC4644b;
import com.quizlet.quizletandroid.ui.library.C4676v;
import com.quizlet.quizletandroid.ui.library.InterfaceC4646d;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.c5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3594c5 {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 function0) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1221281629);
        if ((i & 6) == 0) {
            i2 = (c0814p2.f(qVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function0) ? 32 : 16;
        }
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            int i3 = i2 << 3;
            c0814p = c0814p2;
            Y4.a(AbstractC3106b5.d(c0814p2, R.string.continue_with_facebook), qVar, function0, false, false, null, null, 0L, 0L, C4097w.a, com.quizlet.themes.e.a(c0814p2).c.d(c0814p2), null, false, c0814p, (i3 & ContentType.LONG_FORM_ON_DEMAND) | 805306368 | (i3 & 896), 384, 2552);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.buttons.U(qVar, function0, i, 0);
        }
    }

    public static final void b(InterfaceC4646d viewModel, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.q qVar2 = qVar;
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-112602432);
        int i2 = i | (c0814p2.f(viewModel) ? 4 : 2) | (c0814p2.f(qVar2) ? 32 : 16);
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p2.j(androidx.lifecycle.compose.g.a);
            c0814p2.X(-937446599);
            int i3 = i2 & 14;
            boolean zH = (i3 == 4) | c0814p2.h(j);
            Object objI = c0814p2.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zH || objI == v) {
                objI = new com.quizlet.features.setpage.header.ui.g(15, j, viewModel);
                c0814p2.i0(objI);
            }
            c0814p2.p(false);
            C0776c.d(j, (Function1) objI, c0814p2);
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(((com.quizlet.quizletandroid.ui.library.c0) viewModel).t, c0814p2);
            boolean zIsEmpty = ((com.quizlet.quizletandroid.ui.library.data.J) interfaceC0773a0M.getValue()).a.isEmpty();
            if (zIsEmpty) {
                c0814p2.X(-937430648);
                AbstractC3249r5.a(qVar2, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), c0814p2, (i2 >> 3) & 14, 0);
                c0814p = c0814p2;
                c0814p.p(false);
                qVar2 = qVar;
            } else {
                if (zIsEmpty) {
                    throw com.google.android.gms.measurement.internal.Z.j(-937430877, c0814p2, false);
                }
                c0814p2.X(1004567461);
                com.quizlet.quizletandroid.ui.library.data.J j2 = (com.quizlet.quizletandroid.ui.library.data.J) interfaceC0773a0M.getValue();
                c0814p2.X(-937423638);
                boolean z = i3 == 4;
                Object objI2 = c0814p2.I();
                if (z || objI2 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onDropdownMenuChanged", "onDropdownMenuChanged(I)V", 0, 12);
                    c0814p2.i0(sVar);
                    objI2 = sVar;
                }
                kotlin.reflect.f fVar = (kotlin.reflect.f) objI2;
                c0814p2.p(false);
                c0814p2.X(-937421596);
                boolean z2 = i3 == 4;
                Object objI3 = c0814p2.I();
                if (z2 || objI3 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar2 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onFilterChanged", "onFilterChanged(Ljava/lang/String;)V", 0, 13);
                    c0814p2.i0(sVar2);
                    objI3 = sVar2;
                }
                kotlin.reflect.f fVar2 = (kotlin.reflect.f) objI3;
                c0814p2.p(false);
                c0814p2.X(-937419674);
                boolean z3 = i3 == 4;
                Object objI4 = c0814p2.I();
                if (z3 || objI4 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar3 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onStudySetClicked", "onStudySetClicked(J)V", 0, 14);
                    c0814p2.i0(sVar3);
                    objI4 = sVar3;
                }
                kotlin.reflect.f fVar3 = (kotlin.reflect.f) objI4;
                c0814p2.p(false);
                c0814p2.X(-937417756);
                boolean z4 = i3 == 4;
                Object objI5 = c0814p2.I();
                if (z4 || objI5 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar4 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onFolderClicked", "onFolderClicked(J)V", 0, 15);
                    c0814p2.i0(sVar4);
                    objI5 = sVar4;
                }
                kotlin.reflect.f fVar4 = (kotlin.reflect.f) objI5;
                c0814p2.p(false);
                c0814p2.X(-937415933);
                boolean z5 = i3 == 4;
                Object objI6 = c0814p2.I();
                if (z5 || objI6 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar5 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onClassClicked", "onClassClicked(J)V", 0, 16);
                    c0814p2.i0(sVar5);
                    objI6 = sVar5;
                }
                kotlin.reflect.f fVar5 = (kotlin.reflect.f) objI6;
                c0814p2.p(false);
                c0814p2.X(-937414042);
                boolean z6 = i3 == 4;
                Object objI7 = c0814p2.I();
                if (z6 || objI7 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.n nVar = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, viewModel, InterfaceC4646d.class, "onNewClassClicked", "onNewClassClicked()V", 0, 7);
                    c0814p2.i0(nVar);
                    objI7 = nVar;
                }
                kotlin.reflect.f fVar6 = (kotlin.reflect.f) objI7;
                c0814p2.p(false);
                c0814p2.X(-937412025);
                boolean z7 = i3 == 4;
                Object objI8 = c0814p2.I();
                if (z7 || objI8 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.n nVar2 = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, viewModel, InterfaceC4646d.class, "onNewFolderClicked", "onNewFolderClicked()V", 0, 8);
                    c0814p2.i0(nVar2);
                    objI8 = nVar2;
                }
                kotlin.reflect.f fVar7 = (kotlin.reflect.f) objI8;
                c0814p2.p(false);
                c0814p2.X(-937410043);
                boolean z8 = i3 == 4;
                Object objI9 = c0814p2.I();
                if (z8 || objI9 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.n nVar3 = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, viewModel, InterfaceC4646d.class, "onNewNoteClicked", "onNewNoteClicked()V", 0, 9);
                    c0814p2.i0(nVar3);
                    objI9 = nVar3;
                }
                kotlin.reflect.f fVar8 = (kotlin.reflect.f) objI9;
                c0814p2.p(false);
                c0814p2.X(-937407991);
                boolean z9 = i3 == 4;
                Object objI10 = c0814p2.I();
                if (z9 || objI10 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.n nVar4 = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, viewModel, InterfaceC4646d.class, "onNewStudySetClicked", "onNewStudySetClicked()V", 0, 5);
                    c0814p2.i0(nVar4);
                    objI10 = nVar4;
                }
                kotlin.reflect.f fVar9 = (kotlin.reflect.f) objI10;
                c0814p2.p(false);
                c0814p2.X(-937406013);
                boolean z10 = i3 == 4;
                Object objI11 = c0814p2.I();
                if (z10 || objI11 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar6 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onPageSelected", "onPageSelected(I)V", 0, 4);
                    c0814p2.i0(sVar6);
                    objI11 = sVar6;
                }
                kotlin.reflect.f fVar10 = (kotlin.reflect.f) objI11;
                c0814p2.p(false);
                c0814p2.X(-937404247);
                boolean z11 = i3 == 4;
                Object objI12 = c0814p2.I();
                if (z11 || objI12 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar7 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onCreateNewItemClick", "onCreateNewItemClick(Lcom/quizlet/data/model/LibraryTab;)V", 0, 5);
                    c0814p2.i0(sVar7);
                    objI12 = sVar7;
                }
                kotlin.reflect.f fVar11 = (kotlin.reflect.f) objI12;
                c0814p2.p(false);
                c0814p2.X(-937402302);
                boolean z12 = i3 == 4;
                Object objI13 = c0814p2.I();
                if (z12 || objI13 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar8 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onNoteClicked", "onNoteClicked(Ljava/lang/String;)V", 0, 6);
                    c0814p2.i0(sVar8);
                    objI13 = sVar8;
                }
                kotlin.reflect.f fVar12 = (kotlin.reflect.f) objI13;
                c0814p2.p(false);
                c0814p2.X(-937400211);
                boolean z13 = i3 == 4;
                Object objI14 = c0814p2.I();
                if (z13 || objI14 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.n nVar5 = new com.quizlet.quizletandroid.ui.globalnav.composable.n(0, viewModel, InterfaceC4646d.class, "onNewPracticeTestClicked", "onNewPracticeTestClicked()V", 0, 6);
                    c0814p2.i0(nVar5);
                    objI14 = nVar5;
                }
                kotlin.reflect.f fVar13 = (kotlin.reflect.f) objI14;
                c0814p2.p(false);
                c0814p2.X(-937397878);
                boolean z14 = i3 == 4;
                Object objI15 = c0814p2.I();
                if (z14 || objI15 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar9 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onPracticeTestClicked", "onPracticeTestClicked(Ljava/lang/String;)V", 0, 7);
                    c0814p2.i0(sVar9);
                    objI15 = sVar9;
                }
                kotlin.reflect.f fVar14 = (kotlin.reflect.f) objI15;
                c0814p2.p(false);
                c0814p2.X(-937395834);
                boolean z15 = i3 == 4;
                Object objI16 = c0814p2.I();
                if (z15 || objI16 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar10 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onTextbookClicked", "onTextbookClicked(Ljava/lang/String;)V", 0, 8);
                    c0814p2.i0(sVar10);
                    objI16 = sVar10;
                }
                kotlin.reflect.f fVar15 = (kotlin.reflect.f) objI16;
                c0814p2.p(false);
                c0814p2.X(-937393650);
                boolean z16 = i3 == 4;
                Object objI17 = c0814p2.I();
                if (z16 || objI17 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar11 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onTextbookExerciseClicked", "onTextbookExerciseClicked(Ljava/lang/String;)V", 0, 9);
                    c0814p2.i0(sVar11);
                    objI17 = sVar11;
                }
                kotlin.reflect.f fVar16 = (kotlin.reflect.f) objI17;
                c0814p2.p(false);
                c0814p2.X(-937391119);
                boolean z17 = i3 == 4;
                Object objI18 = c0814p2.I();
                if (z17 || objI18 == v) {
                    com.quizlet.quizletandroid.ui.globalnav.composable.s sVar12 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onExplanationQuestionClicked", "onExplanationQuestionClicked(Ljava/lang/String;)V", 0, 10);
                    c0814p2.i0(sVar12);
                    objI18 = sVar12;
                }
                kotlin.reflect.f fVar17 = (kotlin.reflect.f) objI18;
                c0814p2.p(false);
                c0814p2.X(-937388827);
                boolean z18 = i3 == 4;
                Object objI19 = c0814p2.I();
                if (z18 || objI19 == v) {
                    objI19 = new com.quizlet.quizletandroid.ui.globalnav.composable.s(1, viewModel, InterfaceC4646d.class, "onItemImpression", "onItemImpression(Lcom/quizlet/quizletandroid/ui/library/data/LibraryImpressionEvent;)V", 0, 11);
                    c0814p2.i0(objI19);
                }
                c0814p2.p(false);
                qVar2 = qVar;
                d(j2, qVar2, (Function1) fVar, (Function1) fVar2, (Function1) fVar3, (Function1) fVar4, (Function1) fVar12, (Function1) fVar5, (Function1) fVar14, (Function0) fVar9, (Function0) fVar7, (Function0) fVar8, (Function0) fVar6, (Function0) fVar13, (Function1) fVar15, (Function1) fVar16, (Function1) fVar17, (Function1) ((kotlin.reflect.f) objI19), (Function1) fVar10, (Function1) fVar11, c0814p2, i2 & ContentType.LONG_FORM_ON_DEMAND, 0);
                c0814p = c0814p2;
                c0814p.p(false);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questionnaire.screens.d(viewModel, qVar2, i, 20);
        }
    }

    public static final void c(kotlinx.collections.immutable.b bVar, C0466e c0466e, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(930320116);
        int i2 = i | (c0814p.h(bVar) ? 4 : 2) | (c0814p.f(c0466e) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128);
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            Object objI = c0814p.I();
            if (objI == C0804k.a) {
                objI = C0776c.n(kotlin.coroutines.n.a, c0814p);
                c0814p.i0(objI);
            }
            AbstractC3619f6.a(c0466e.j(), qVar, 0L, androidx.compose.runtime.internal.e.e(-1462477145, new C4676v(bVar, c0466e, (kotlinx.coroutines.C) objI, 0), c0814p), c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | 3072, 4);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(i, 27, bVar, c0466e, qVar);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:108:0x0153  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0165  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x016a  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x017e  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x0185  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x01b8  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x01bd  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x01d3  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x01da  */
    /* JADX WARN: Removed duplicated region for block: B:157:0x01ef  */
    /* JADX WARN: Removed duplicated region for block: B:158:0x01f4  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x0205  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x020a  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x021c  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x0221  */
    /* JADX WARN: Removed duplicated region for block: B:180:0x0234  */
    /* JADX WARN: Removed duplicated region for block: B:181:0x0237  */
    /* JADX WARN: Removed duplicated region for block: B:188:0x024d  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x027c  */
    /* JADX WARN: Removed duplicated region for block: B:195:0x027e  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x0281  */
    /* JADX WARN: Removed duplicated region for block: B:199:0x0289  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x02a7  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x02aa  */
    /* JADX WARN: Removed duplicated region for block: B:209:0x02c7  */
    /* JADX WARN: Removed duplicated region for block: B:211:0x02ca  */
    /* JADX WARN: Removed duplicated region for block: B:216:0x02e8  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x030b  */
    /* JADX WARN: Removed duplicated region for block: B:223:0x0311  */
    /* JADX WARN: Removed duplicated region for block: B:228:0x0330  */
    /* JADX WARN: Removed duplicated region for block: B:233:0x034f  */
    /* JADX WARN: Removed duplicated region for block: B:238:0x036e  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0050  */
    /* JADX WARN: Removed duplicated region for block: B:242:0x038b  */
    /* JADX WARN: Removed duplicated region for block: B:244:0x038f  */
    /* JADX WARN: Removed duplicated region for block: B:248:0x03ac  */
    /* JADX WARN: Removed duplicated region for block: B:250:0x03b0  */
    /* JADX WARN: Removed duplicated region for block: B:254:0x03cd  */
    /* JADX WARN: Removed duplicated region for block: B:256:0x03d1  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0055  */
    /* JADX WARN: Removed duplicated region for block: B:261:0x03f4  */
    /* JADX WARN: Removed duplicated region for block: B:263:0x03fa  */
    /* JADX WARN: Removed duplicated region for block: B:268:0x041d  */
    /* JADX WARN: Removed duplicated region for block: B:270:0x0423  */
    /* JADX WARN: Removed duplicated region for block: B:275:0x0441  */
    /* JADX WARN: Removed duplicated region for block: B:279:0x045e  */
    /* JADX WARN: Removed duplicated region for block: B:281:0x0462  */
    /* JADX WARN: Removed duplicated region for block: B:286:0x0485  */
    /* JADX WARN: Removed duplicated region for block: B:288:0x048b  */
    /* JADX WARN: Removed duplicated region for block: B:293:0x04ae  */
    /* JADX WARN: Removed duplicated region for block: B:295:0x04b4  */
    /* JADX WARN: Removed duplicated region for block: B:300:0x04d7  */
    /* JADX WARN: Removed duplicated region for block: B:302:0x04dd  */
    /* JADX WARN: Removed duplicated region for block: B:307:0x0500  */
    /* JADX WARN: Removed duplicated region for block: B:311:0x051d  */
    /* JADX WARN: Removed duplicated region for block: B:339:0x0747  */
    /* JADX WARN: Removed duplicated region for block: B:343:0x080e  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:350:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00d3  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0113  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0131  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0136  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(final com.quizlet.quizletandroid.ui.library.data.J r54, androidx.compose.ui.q r55, kotlin.jvm.functions.Function1 r56, kotlin.jvm.functions.Function1 r57, kotlin.jvm.functions.Function1 r58, kotlin.jvm.functions.Function1 r59, kotlin.jvm.functions.Function1 r60, kotlin.jvm.functions.Function1 r61, kotlin.jvm.functions.Function1 r62, kotlin.jvm.functions.Function0 r63, kotlin.jvm.functions.Function0 r64, kotlin.jvm.functions.Function0 r65, kotlin.jvm.functions.Function0 r66, kotlin.jvm.functions.Function0 r67, kotlin.jvm.functions.Function1 r68, kotlin.jvm.functions.Function1 r69, kotlin.jvm.functions.Function1 r70, kotlin.jvm.functions.Function1 r71, kotlin.jvm.functions.Function1 r72, kotlin.jvm.functions.Function1 r73, androidx.compose.runtime.InterfaceC0806l r74, final int r75, final int r76) {
        /*
            Method dump skipped, instructions count: 2081
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3594c5.d(com.quizlet.quizletandroid.ui.library.data.J, androidx.compose.ui.q, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final void e(int i, InterfaceC0806l interfaceC0806l, Function0 function0, boolean z) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-292930296);
        if ((((c0814p.h(function0) ? 4 : 2) | i | (c0814p.g(z) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3691o6.b(AbstractC4644b.a, null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), 0L, 0L, null, null, androidx.compose.runtime.internal.e.e(-1593469495, new com.quizlet.features.flashcards.views.c(z, function0, 3), c0814p), c0814p, 14155782, 58);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.input.c(i, 3, function0, z);
        }
    }
}
