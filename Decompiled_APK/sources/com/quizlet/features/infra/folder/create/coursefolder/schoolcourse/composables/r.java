package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.transition.C1412o;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3098a6;
import com.google.android.gms.internal.mlkit_vision_barcode.T5;
import com.google.android.gms.internal.mlkit_vision_barcode.U5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3351i2;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;
import com.google.android.gms.internal.mlkit_vision_common.N3;
import com.google.android.gms.internal.mlkit_vision_common.S2;
import com.google.android.gms.internal.mlkit_vision_common.V2;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3621g0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3626g5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3736u4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.H;
import com.google.android.gms.internal.mlkit_vision_document_scanner.I;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y6;
import com.quizlet.generated.enums.EnumC4501m0;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ r(androidx.compose.ui.q qVar, com.quizlet.features.settings.data.states.d dVar, String str, Function1 function1, com.quizlet.assembly.compose.input.n nVar, int i) {
        this.a = 11;
        this.e = qVar;
        this.c = dVar;
        this.d = str;
        this.b = function1;
        this.f = nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.e;
                Function0 function0 = (Function0) this.d;
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b) this.f;
                T5.a(qVar, (Function1) this.b, (Function1) this.c, function0, bVar, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(9);
                Function1 function1 = (Function1) this.c;
                Function0 function02 = (Function0) this.d;
                U5.a((com.quizlet.assembly.compose.modals.x) this.e, (androidx.compose.ui.n) this.f, (Function1) this.b, function1, function02, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(385);
                Function2 function2 = (Function2) this.f;
                Function0 function03 = (Function0) this.d;
                com.quizlet.features.infra.folder.menu.composable.k.a((com.quizlet.features.infra.folder.menu.screenstates.d) this.c, (androidx.compose.ui.q) this.e, (Function1) this.b, function2, function03, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(3505);
                kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) this.c;
                com.quizlet.features.notes.upload.viewmodels.e eVar = (com.quizlet.features.notes.upload.viewmodels.e) this.f;
                AbstractC3328d.b((Function0) this.d, (Function0) this.e, (Function2) this.b, cVar, eVar, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1);
                Function0 function04 = (Function0) this.d;
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.e;
                AbstractC3328d.a((com.quizlet.features.notes.upload.states.c) this.c, (String) this.f, (Function1) this.b, function04, qVar2, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(1);
                com.quizlet.features.paywall.state.c cVar2 = (com.quizlet.features.paywall.state.c) this.e;
                Function0 function05 = (Function0) this.c;
                Function0 function06 = (Function0) this.f;
                K1.d(cVar2, (androidx.compose.ui.n) this.b, (Function0) this.d, function05, function06, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(1);
                com.quizlet.features.practicetest.results.data.e eVar2 = (com.quizlet.features.practicetest.results.data.e) this.b;
                com.quizlet.features.practicetest.results.data.e eVar3 = (com.quizlet.features.practicetest.results.data.e) this.c;
                EnumC4501m0 enumC4501m0 = (EnumC4501m0) this.f;
                androidx.compose.ui.q qVar3 = (androidx.compose.ui.q) this.e;
                AbstractC3351i2.a(eVar2, eVar3, (kotlinx.collections.immutable.e) this.d, enumC4501m0, qVar3, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(9);
                Function0 function07 = (Function0) this.d;
                C1412o.c(iH8, (InterfaceC0806l) obj, (androidx.compose.ui.q) this.e, (com.quizlet.assembly.compose.modals.x) this.c, function07, (Function1) this.b, (kotlinx.collections.immutable.e) this.f);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(1);
                androidx.compose.ui.q qVar4 = (androidx.compose.ui.q) this.e;
                Function0 function08 = (Function0) this.d;
                com.quizlet.features.questionnaire.screens.l.e((com.quizlet.features.questionnaire.navigation.b) this.b, (com.quizlet.features.questionnaire.steps.h) this.c, (com.quizlet.data.interactor.course.a) this.f, qVar4, function08, (InterfaceC0806l) obj, iH9);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(1);
                Function1 function12 = (Function1) this.b;
                Function0 function09 = (Function0) this.d;
                com.google.android.gms.internal.mlkit_vision_common.A.c((com.quizlet.assembly.compose.components.flashcards.b) this.c, (com.quizlet.features.setpage.studypreview.data.a) this.f, (androidx.compose.ui.q) this.e, function12, function09, (InterfaceC0806l) obj, iH10);
                break;
            case 10:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(1);
                Function1 function13 = (Function1) this.b;
                androidx.compose.ui.q qVar5 = (androidx.compose.ui.q) this.e;
                com.google.android.gms.internal.mlkit_vision_common.D.a((com.quizlet.features.setpage.termlist.data.m) this.c, (com.quizlet.assembly.compose.menu.s) this.f, (Function0) this.d, function13, qVar5, (InterfaceC0806l) obj, iH11);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(1);
                Function1 function14 = (Function1) this.b;
                com.quizlet.assembly.compose.input.n nVar = (com.quizlet.assembly.compose.input.n) this.f;
                S2.a((androidx.compose.ui.q) this.e, (com.quizlet.features.settings.data.states.d) this.c, (String) this.d, function14, nVar, (InterfaceC0806l) obj, iH12);
                break;
            case 12:
                ((Integer) obj2).getClass();
                int iH13 = C0776c.H(1);
                androidx.compose.ui.q qVar6 = (androidx.compose.ui.q) this.e;
                com.quizlet.assembly.compose.input.n nVar2 = (com.quizlet.assembly.compose.input.n) this.f;
                V2.a((com.quizlet.features.settings.data.states.l) this.c, (String) this.d, (Function1) this.b, qVar6, nVar2, (InterfaceC0806l) obj, iH13);
                break;
            case 13:
                ((Integer) obj2).getClass();
                int iH14 = C0776c.H(1);
                androidx.compose.ui.n nVar3 = (androidx.compose.ui.n) this.c;
                String str = (String) this.f;
                N3.e((String) this.e, (androidx.compose.ui.graphics.painter.b) this.b, (Function0) this.d, nVar3, str, (InterfaceC0806l) obj, iH14);
                break;
            case 14:
                ((Integer) obj2).getClass();
                int iH15 = C0776c.H(1);
                Function1 function15 = (Function1) this.c;
                androidx.compose.ui.q qVar7 = (androidx.compose.ui.q) this.e;
                Y3.a((com.quizlet.features.universaluploadflow.flashcards.data.p) this.f, (Function0) this.d, (Function1) this.b, function15, qVar7, (InterfaceC0806l) obj, iH15);
                break;
            case 15:
                ((Integer) obj2).getClass();
                int iH16 = C0776c.H(3505);
                Function0 function010 = (Function0) this.c;
                com.quizlet.features.universaluploadflow.pastetext.viewmodel.a aVar = (com.quizlet.features.universaluploadflow.pastetext.viewmodel.a) this.f;
                AbstractC3448e4.d((Function0) this.d, (Function0) this.e, (Function1) this.b, function010, aVar, (InterfaceC0806l) obj, iH16);
                break;
            case 16:
                ((Integer) obj2).getClass();
                int iH17 = C0776c.H(1);
                String str2 = (String) this.c;
                androidx.compose.ui.q qVar8 = (androidx.compose.ui.q) this.e;
                com.quizlet.login.magiclink.viewmodel.b bVar2 = (com.quizlet.login.magiclink.viewmodel.b) this.f;
                H.b(str2, (Function1) this.b, (Function0) this.d, qVar8, bVar2, (InterfaceC0806l) obj, iH17);
                break;
            case 17:
                ((Integer) obj2).getClass();
                int iH18 = C0776c.H(1);
                Function0 function011 = (Function0) this.d;
                Function0 function012 = (Function0) this.f;
                I.a((String) this.c, (Function1) this.b, (androidx.compose.ui.q) this.e, function011, function012, (InterfaceC0806l) obj, iH18);
                break;
            case 18:
                ((Integer) obj2).getClass();
                int iH19 = C0776c.H(1);
                androidx.compose.ui.q qVar9 = (androidx.compose.ui.q) this.e;
                String str3 = (String) this.f;
                AbstractC3621g0.b((String) this.d, (Function1) this.b, (Function1) this.c, qVar9, str3, (InterfaceC0806l) obj, iH19);
                break;
            case 19:
                ((Integer) obj2).getClass();
                int iH20 = C0776c.H(1);
                com.quizlet.quizletandroid.ui.classcreation.data.b bVar3 = (com.quizlet.quizletandroid.ui.classcreation.data.b) this.c;
                com.quizlet.quizletandroid.ui.classcreation.data.a aVar2 = (com.quizlet.quizletandroid.ui.classcreation.data.a) this.f;
                AbstractC3736u4.d((kotlin.jvm.functions.c) this.e, (Function0) this.d, (Function0) this.b, bVar3, aVar2, (InterfaceC0806l) obj, iH20);
                break;
            case 20:
                ((Integer) obj2).getClass();
                int iH21 = C0776c.H(1);
                Function1 function16 = (Function1) this.d;
                com.quizlet.library.viewmodels.s sVar = (com.quizlet.library.viewmodels.s) this.f;
                AbstractC3626g5.d((Function1) this.b, (Function1) this.c, (Function1) this.e, function16, sVar, (InterfaceC0806l) obj, iH21);
                break;
            case 21:
                ((Integer) obj2).getClass();
                int iH22 = C0776c.H(1);
                com.quizlet.uicommon.ui.common.util.d dVar = (com.quizlet.uicommon.ui.common.util.d) this.d;
                com.quizlet.uicommon.ui.common.util.d dVar2 = (com.quizlet.uicommon.ui.common.util.d) this.f;
                Function1 function17 = (Function1) this.c;
                androidx.compose.ui.q qVar10 = (androidx.compose.ui.q) this.e;
                Y6.a(dVar, dVar2, (Function1) this.b, function17, qVar10, (InterfaceC0806l) obj, iH22);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((Integer) obj2).getClass();
                int iH23 = C0776c.H(1);
                Function1 function18 = (Function1) this.c;
                androidx.compose.ui.n nVar4 = (androidx.compose.ui.n) this.f;
                com.google.mlkit.common.model.a.c((com.quizlet.quizletandroid.ui.subject.viewmodel.g) this.e, (Function2) this.d, (Function1) this.b, function18, nVar4, (InterfaceC0806l) obj, iH23);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH24 = C0776c.H(1);
                Function0 function013 = (Function0) this.d;
                androidx.compose.ui.q qVar11 = (androidx.compose.ui.q) this.e;
                AbstractC3098a6.a((String) this.b, (String) this.c, (String) this.f, function013, qVar11, (InterfaceC0806l) obj, iH24);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ r(androidx.compose.ui.q qVar, Function1 function1, Function1 function12, Function0 function0, com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.b bVar, int i) {
        this.a = 0;
        this.e = qVar;
        this.b = function1;
        this.c = function12;
        this.d = function0;
        this.f = bVar;
    }

    public /* synthetic */ r(com.quizlet.assembly.compose.components.flashcards.b bVar, com.quizlet.features.setpage.studypreview.data.a aVar, androidx.compose.ui.q qVar, Function1 function1, Function0 function0, int i) {
        this.a = 9;
        this.c = bVar;
        this.f = aVar;
        this.e = qVar;
        this.b = function1;
        this.d = function0;
    }

    public /* synthetic */ r(com.quizlet.assembly.compose.modals.x xVar, androidx.compose.ui.n nVar, Function1 function1, Function1 function12, Function0 function0, int i) {
        this.a = 1;
        this.e = xVar;
        this.f = nVar;
        this.b = function1;
        this.c = function12;
        this.d = function0;
    }

    public /* synthetic */ r(com.quizlet.features.infra.folder.menu.screenstates.d dVar, androidx.compose.ui.q qVar, Function1 function1, Function2 function2, Function0 function0, int i) {
        this.a = 2;
        this.c = dVar;
        this.e = qVar;
        this.b = function1;
        this.f = function2;
        this.d = function0;
    }

    public /* synthetic */ r(com.quizlet.features.practicetest.results.data.e eVar, com.quizlet.features.practicetest.results.data.e eVar2, kotlinx.collections.immutable.e eVar3, EnumC4501m0 enumC4501m0, androidx.compose.ui.q qVar, int i) {
        this.a = 6;
        this.b = eVar;
        this.c = eVar2;
        this.d = eVar3;
        this.f = enumC4501m0;
        this.e = qVar;
    }

    public /* synthetic */ r(com.quizlet.features.questionnaire.navigation.b bVar, com.quizlet.features.questionnaire.steps.h hVar, com.quizlet.data.interactor.course.a aVar, androidx.compose.ui.q qVar, Function0 function0, int i) {
        this.a = 8;
        this.b = bVar;
        this.c = hVar;
        this.f = aVar;
        this.e = qVar;
        this.d = function0;
    }

    public /* synthetic */ r(com.quizlet.features.setpage.termlist.data.m mVar, com.quizlet.assembly.compose.menu.s sVar, Function0 function0, Function1 function1, androidx.compose.ui.q qVar, int i) {
        this.a = 10;
        this.c = mVar;
        this.f = sVar;
        this.d = function0;
        this.b = function1;
        this.e = qVar;
    }

    public /* synthetic */ r(com.quizlet.features.settings.data.states.l lVar, String str, Function1 function1, androidx.compose.ui.q qVar, com.quizlet.assembly.compose.input.n nVar, int i) {
        this.a = 12;
        this.c = lVar;
        this.d = str;
        this.b = function1;
        this.e = qVar;
        this.f = nVar;
    }

    public /* synthetic */ r(com.quizlet.features.universaluploadflow.flashcards.data.p pVar, Function0 function0, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, int i) {
        this.a = 14;
        this.f = pVar;
        this.d = function0;
        this.b = function1;
        this.c = function12;
        this.e = qVar;
    }

    public /* synthetic */ r(com.quizlet.uicommon.ui.common.util.d dVar, com.quizlet.uicommon.ui.common.util.d dVar2, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, int i) {
        this.a = 21;
        this.d = dVar;
        this.f = dVar2;
        this.b = function1;
        this.c = function12;
        this.e = qVar;
    }

    public /* synthetic */ r(Object obj, Object obj2, Function0 function0, Object obj3, Object obj4, int i, int i2) {
        this.a = i2;
        this.e = obj;
        this.b = obj2;
        this.d = function0;
        this.c = obj3;
        this.f = obj4;
    }

    public /* synthetic */ r(Object obj, Object obj2, Function1 function1, Function0 function0, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.f = obj2;
        this.b = function1;
        this.d = function0;
        this.e = qVar;
    }

    public /* synthetic */ r(Object obj, InterfaceC4938g interfaceC4938g, InterfaceC4938g interfaceC4938g2, Object obj2, Object obj3, int i, int i2) {
        this.a = i2;
        this.e = obj;
        this.d = interfaceC4938g;
        this.b = interfaceC4938g2;
        this.c = obj2;
        this.f = obj3;
    }

    public /* synthetic */ r(String str, String str2, String str3, Function0 function0, androidx.compose.ui.q qVar, int i) {
        this.a = 23;
        this.b = str;
        this.c = str2;
        this.f = str3;
        this.d = function0;
        this.e = qVar;
    }

    public /* synthetic */ r(String str, Function1 function1, androidx.compose.ui.q qVar, Function0 function0, Function0 function02, int i) {
        this.a = 17;
        this.c = str;
        this.b = function1;
        this.e = qVar;
        this.d = function0;
        this.f = function02;
    }

    public /* synthetic */ r(String str, Function1 function1, Function0 function0, androidx.compose.ui.q qVar, com.quizlet.login.magiclink.viewmodel.b bVar, int i) {
        this.a = 16;
        this.c = str;
        this.b = function1;
        this.d = function0;
        this.e = qVar;
        this.f = bVar;
    }

    public /* synthetic */ r(String str, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, String str2, int i) {
        this.a = 18;
        this.d = str;
        this.b = function1;
        this.c = function12;
        this.e = qVar;
        this.f = str2;
    }

    public /* synthetic */ r(Function0 function0, Function0 function02, InterfaceC4938g interfaceC4938g, InterfaceC4938g interfaceC4938g2, Object obj, int i, int i2) {
        this.a = i2;
        this.d = function0;
        this.e = function02;
        this.b = interfaceC4938g;
        this.c = interfaceC4938g2;
        this.f = obj;
    }

    public /* synthetic */ r(Function1 function1, Function1 function12, Function1 function13, Function1 function14, com.quizlet.library.viewmodels.s sVar, int i) {
        this.a = 20;
        this.b = function1;
        this.c = function12;
        this.e = function13;
        this.d = function14;
        this.f = sVar;
    }
}
