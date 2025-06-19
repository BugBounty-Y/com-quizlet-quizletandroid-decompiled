package com.quizlet.explanations.questiondetail.ui.composables;

import androidx.compose.material3.O3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3134e6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import com.google.android.gms.internal.mlkit_vision_barcode.Z5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3379p2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3394t2;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import com.google.android.gms.internal.mlkit_vision_common.Y2;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3581b0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.internal.mlkit_vision_document_scanner.k7;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.practicetest.takingtest.data.C4412f;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4415i;
import com.quizlet.login.login.data.w;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.W;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ e(H h, com.quizlet.features.questionnaire.navigation.b bVar, com.quizlet.features.questionnaire.steps.h hVar, com.quizlet.data.interactor.course.a aVar, androidx.compose.ui.q qVar, Function0 function0, int i) {
        this.a = 9;
        this.d = h;
        this.b = bVar;
        this.e = hVar;
        this.f = aVar;
        this.g = qVar;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                Function1 function1 = (Function1) this.f;
                O3 o3 = (O3) this.g;
                k7.a((com.quizlet.explanations.questiondetail.viewmodel.f) this.d, (androidx.compose.ui.n) this.b, (com.quizlet.features.infra.folder.menu.viewmodel.n) this.e, (Function0) this.c, function1, o3, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                com.quizlet.features.flashcards.data.q qVar = (com.quizlet.features.flashcards.data.q) this.d;
                Function0 function0 = (Function0) this.f;
                Function0 function02 = (Function0) this.g;
                AbstractC3173j0.c(qVar, (androidx.compose.ui.n) this.b, (com.quizlet.features.flashcards.screens.a) this.e, (Function0) this.c, function0, function02, (InterfaceC0806l) obj, iH2);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(9);
                Function0 function03 = (Function0) this.c;
                Function0 function04 = (Function0) this.g;
                AbstractC3134e6.a((x) this.d, (com.quizlet.features.infra.folder.menu.screenstates.d) this.b, (androidx.compose.ui.q) this.e, (Function1) this.f, function03, function04, (InterfaceC0806l) obj, iH3);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(385);
                Function0 function05 = (Function0) this.c;
                Function0 function06 = (Function0) this.g;
                com.quizlet.features.infra.folder.menu.composable.k.b((com.quizlet.features.infra.folder.menu.screenstates.d) this.d, (androidx.compose.ui.q) this.b, (Function1) this.f, (Function2) this.e, function05, function06, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(1);
                m2 m2Var = (m2) this.b;
                AddMaterialFolderData addMaterialFolderData = (AddMaterialFolderData) this.f;
                H h = (H) this.g;
                com.quizlet.features.notes.upload.navigation.c.a((com.quizlet.features.notes.manager.a) this.d, m2Var, (String) this.e, (kotlinx.collections.immutable.b) this.c, addMaterialFolderData, h, (InterfaceC0806l) obj, iH5);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(1);
                String str = (String) this.b;
                H h2 = (H) this.f;
                com.quizlet.features.practicetest.navigation.d dVar = (com.quizlet.features.practicetest.navigation.d) this.g;
                com.quizlet.features.practicetest.navigation.c.a((String) this.d, str, (String) this.e, (String) this.c, h2, dVar, (InterfaceC0806l) obj, iH6);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(1);
                Function2 function2 = (Function2) this.f;
                com.quizlet.features.practicetest.results.viewmodel.a aVar = (com.quizlet.features.practicetest.results.viewmodel.a) this.g;
                AbstractC3339f2.e((W) this.d, (kotlin.jvm.functions.d) this.b, (Function2) this.e, (Function2) this.c, function2, aVar, (InterfaceC0806l) obj, iH7);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(1);
                Function0 function07 = (Function0) this.f;
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.g;
                AbstractC3379p2.a((Function0) this.c, (Function0) this.d, (Function0) this.b, (Function0) this.e, function07, qVar2, (InterfaceC0806l) obj, iH8);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(1);
                Function0 function08 = (Function0) this.c;
                androidx.compose.ui.q qVar3 = (androidx.compose.ui.q) this.g;
                AbstractC3394t2.a((C4412f) this.d, (InterfaceC4415i) this.b, (Function1) this.f, (Function1) this.e, function08, qVar3, (InterfaceC0806l) obj, iH9);
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(1);
                androidx.compose.ui.q qVar4 = (androidx.compose.ui.q) this.g;
                Function0 function09 = (Function0) this.c;
                com.quizlet.features.questionnaire.screens.l.c((H) this.d, (com.quizlet.features.questionnaire.navigation.b) this.b, (com.quizlet.features.questionnaire.steps.h) this.e, (com.quizlet.data.interactor.course.a) this.f, qVar4, function09, (InterfaceC0806l) obj, iH10);
                break;
            case 10:
                ((Integer) obj2).getClass();
                int iH11 = C0776c.H(1);
                com.quizlet.features.infra.logout.viewmodels.a aVar2 = (com.quizlet.features.infra.logout.viewmodels.a) this.b;
                com.quizlet.features.settings.viewmodels.n nVar = (com.quizlet.features.settings.viewmodels.n) this.f;
                com.quizlet.features.infra.google.e eVar = (com.quizlet.features.infra.google.e) this.g;
                Y2.b((H) this.d, aVar2, (com.quizlet.quizletandroid.ui.navigationmanagers.h) this.e, (com.quizlet.features.settings.viewmodels.o) this.c, nVar, eVar, (InterfaceC0806l) obj, iH11);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH12 = C0776c.H(1);
                androidx.compose.material3.windowsizeclass.b bVar = (androidx.compose.material3.windowsizeclass.b) this.f;
                Function0 function010 = (Function0) this.c;
                Function0 function011 = (Function0) this.g;
                AbstractC3471i3.b((com.quizlet.features.settings.viewmodels.p) this.d, (H) this.b, (com.quizlet.quizletandroid.ui.navigationmanagers.h) this.e, bVar, function010, function011, (InterfaceC0806l) obj, iH12);
                break;
            case 12:
                ((Integer) obj2).getClass();
                int iH13 = C0776c.H(3505);
                androidx.compose.ui.q qVar5 = (androidx.compose.ui.q) this.e;
                com.quizlet.features.universaluploadflow.flashcards.viewmodel.a aVar3 = (com.quizlet.features.universaluploadflow.flashcards.viewmodel.a) this.g;
                Y3.i((Function0) this.c, (Function0) this.d, (Function1) this.f, (Function0) this.b, qVar5, aVar3, (InterfaceC0806l) obj, iH13);
                break;
            case 13:
                ((Integer) obj2).getClass();
                int iH14 = C0776c.H(1);
                Function1 function12 = (Function1) this.e;
                androidx.compose.ui.q qVar6 = (androidx.compose.ui.q) this.g;
                AbstractC3448e4.a((String) this.d, (com.quizlet.features.universaluploadflow.pastetext.data.m) this.b, (Function0) this.c, (Function1) this.f, function12, qVar6, (InterfaceC0806l) obj, iH14);
                break;
            case 14:
                ((Integer) obj2).getClass();
                int iH15 = C0776c.H(1);
                Function2 function22 = (Function2) this.f;
                androidx.compose.ui.q qVar7 = (androidx.compose.ui.q) this.g;
                P.a((w) this.d, (Function0) this.c, (Function0) this.b, (Function0) this.e, function22, qVar7, (InterfaceC0806l) obj, iH15);
                break;
            case 15:
                ((Integer) obj2).getClass();
                int iH16 = C0776c.H(1);
                Function1 function13 = (Function1) this.f;
                androidx.compose.ui.q qVar8 = (androidx.compose.ui.q) this.g;
                AbstractC3581b0.a((com.quizlet.login.parentemail.data.o) this.d, (Function2) this.b, (Function0) this.c, (Function0) this.e, function13, qVar8, (InterfaceC0806l) obj, iH16);
                break;
            case 16:
                ((Integer) obj2).getClass();
                int iH17 = C0776c.H(24577);
                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m) this.d;
                Function0 function012 = (Function0) this.c;
                Function1 function14 = (Function1) this.g;
                E6.i(mVar, (LearnSettingsUpdateData) this.e, (androidx.compose.ui.n) this.b, (Function1) this.f, function012, function14, (InterfaceC0806l) obj, iH17);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH18 = C0776c.H(1);
                Function0 function013 = (Function0) this.c;
                Function0 function014 = (Function0) this.g;
                Z5.a((String) this.d, (String) this.b, (String) this.e, (String) this.f, function013, function014, (InterfaceC0806l) obj, iH18);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ e(w wVar, Function0 function0, Function0 function02, Function0 function03, Function2 function2, androidx.compose.ui.q qVar, int i) {
        this.a = 14;
        this.d = wVar;
        this.c = function0;
        this.b = function02;
        this.e = function03;
        this.f = function2;
        this.g = qVar;
    }

    public /* synthetic */ e(com.quizlet.login.parentemail.data.o oVar, Function2 function2, Function0 function0, Function0 function02, Function1 function1, androidx.compose.ui.q qVar, int i) {
        this.a = 15;
        this.d = oVar;
        this.b = function2;
        this.c = function0;
        this.e = function02;
        this.f = function1;
        this.g = qVar;
    }

    public /* synthetic */ e(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m mVar, LearnSettingsUpdateData learnSettingsUpdateData, androidx.compose.ui.n nVar, Function1 function1, Function0 function0, Function1 function12, int i) {
        this.a = 16;
        this.d = mVar;
        this.e = learnSettingsUpdateData;
        this.b = nVar;
        this.f = function1;
        this.c = function0;
        this.g = function12;
    }

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, int i, int i2) {
        this.a = i2;
        this.d = obj;
        this.b = obj2;
        this.e = obj3;
        this.c = obj4;
        this.f = obj5;
        this.g = obj6;
    }

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, Object obj4, Function0 function0, Function0 function02, int i, int i2) {
        this.a = i2;
        this.d = obj;
        this.b = obj2;
        this.e = obj3;
        this.f = obj4;
        this.c = function0;
        this.g = function02;
    }

    public /* synthetic */ e(Object obj, Object obj2, Function1 function1, InterfaceC4938g interfaceC4938g, Function0 function0, Object obj3, int i, int i2) {
        this.a = i2;
        this.d = obj;
        this.b = obj2;
        this.f = function1;
        this.e = interfaceC4938g;
        this.c = function0;
        this.g = obj3;
    }

    public /* synthetic */ e(String str, com.quizlet.features.universaluploadflow.pastetext.data.m mVar, Function0 function0, Function1 function1, Function1 function12, androidx.compose.ui.q qVar, int i) {
        this.a = 13;
        this.d = str;
        this.b = mVar;
        this.c = function0;
        this.f = function1;
        this.e = function12;
        this.g = qVar;
    }

    public /* synthetic */ e(Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, androidx.compose.ui.q qVar, int i) {
        this.a = 7;
        this.c = function0;
        this.d = function02;
        this.b = function03;
        this.e = function04;
        this.f = function05;
        this.g = qVar;
    }

    public /* synthetic */ e(Function0 function0, Function0 function02, Function1 function1, Function0 function03, androidx.compose.ui.q qVar, com.quizlet.features.universaluploadflow.flashcards.viewmodel.a aVar, int i) {
        this.a = 12;
        this.c = function0;
        this.d = function02;
        this.f = function1;
        this.b = function03;
        this.e = qVar;
        this.g = aVar;
    }
}
