package com.quizlet.features.questionnaire.screens;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.W;
import androidx.compose.ui.layout.f0;
import androidx.compose.ui.n;
import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.platform.Q0;
import androidx.compose.ui.q;
import androidx.compose.ui.text.C0995g;
import androidx.navigation.H;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_camera.j3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3471i3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3497n;
import com.google.android.gms.internal.mlkit_vision_common.C4;
import com.google.android.gms.internal.mlkit_vision_common.D2;
import com.google.android.gms.internal.mlkit_vision_common.E2;
import com.google.android.gms.internal.mlkit_vision_common.H2;
import com.google.android.gms.internal.mlkit_vision_common.L2;
import com.google.android.gms.internal.mlkit_vision_common.N3;
import com.google.android.gms.internal.mlkit_vision_common.O2;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3581b0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3594c5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3621g0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3625g4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3627g6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3635h6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.I6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.b7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.d7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.g7;
import com.quizlet.features.settings.data.states.y;
import com.quizlet.features.settings.viewmodels.p;
import com.quizlet.features.universaluploadflow.data.K;
import com.quizlet.learn.data.onboarding.u;
import com.quizlet.login.parentemail.data.o;
import com.quizlet.login.signup.data.r;
import com.quizlet.quizletandroid.ui.library.InterfaceC4646d;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.M;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.O;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import com.quizlet.quizletandroid.ui.studymodes.testmode.models.m;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.C4757a;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ d(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                e.a((com.quizlet.features.questionnaire.steps.b) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 1:
                f0 SubcomposeLayout = (f0) obj;
                androidx.compose.ui.unit.a aVar = (androidx.compose.ui.unit.a) obj2;
                Intrinsics.checkNotNullParameter(SubcomposeLayout, "$this$SubcomposeLayout");
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.b;
                W wB = ((J) SubcomposeLayout.n("viewToMeasure", new androidx.compose.runtime.internal.d(true, 1272455859, new com.quizlet.assembly.compose.input.f(dVar, 9))).get(0)).B(aVar.a);
                J j = (J) CollectionsKt.firstOrNull(SubcomposeLayout.n("content", new androidx.compose.runtime.internal.d(true, -473292993, new com.quizlet.assembly.compose.links.e(N5.c(SubcomposeLayout.O(wB.a), SubcomposeLayout.O(wB.b)), dVar, (C0995g) this.c))));
                W wB2 = j != null ? j.B(aVar.a) : null;
                break;
            case 2:
                ((Integer) obj2).getClass();
                j3.a((DiagramData) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 3:
                ((Integer) obj2).getClass();
                AbstractC3497n.a((com.quizlet.features.setpage.header.viewmodel.b) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 4:
                ((Integer) obj2).getClass();
                D2.a((com.quizlet.features.settings.composables.a) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 5:
                ((Integer) obj2).getClass();
                E2.a((com.quizlet.themes.nighttheme.a) this.b, (com.google.mlkit.vision.documentscanner.internal.c) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 6:
                ((Integer) obj2).getClass();
                H2.b((y) this.b, (Function0) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                L2.e((y) this.b, (androidx.compose.runtime.internal.j) this.c, (InterfaceC0806l) obj, iH);
                break;
            case 8:
                ((Integer) obj2).getClass();
                O2.b((com.quizlet.features.settings.data.models.k) this.b, (com.quizlet.data.repository.explanations.myexplanations.a) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 9:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                O2.a((com.quizlet.features.settings.data.models.j) this.b, (Function0) this.c, (InterfaceC0806l) obj, iH2);
                break;
            case 10:
                ((Integer) obj2).getClass();
                AbstractC3471i3.a((p) this.b, (H) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 11:
                ((Integer) obj2).getClass();
                N3.b((K) this.b, (Function1) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 12:
                ((Integer) obj2).getClass();
                S3.c((C0995g) this.b, (n) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 13:
                ((Integer) obj2).getClass();
                AbstractC3448e4.b((com.quizlet.features.universaluploadflow.pastetext.data.p) this.b, (Function1) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 14:
                ((Integer) obj2).getClass();
                com.quizlet.learn.ui.onboarding.e.a((u) this.b, (Function1) this.c, (InterfaceC0806l) obj, C0776c.H(7));
                break;
            case 15:
                ((Integer) obj2).getClass();
                C4.b((com.quizlet.learn.ui.toolbar.d) this.b, (com.google.firebase.crashlytics.internal.common.i) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 16:
                String email = (String) obj;
                String password = (String) obj2;
                Intrinsics.checkNotNullParameter(email, "email");
                Intrinsics.checkNotNullParameter(password, "password");
                Q0 q0 = (Q0) this.b;
                if (q0 != null) {
                    ((C0957n0) q0).a();
                }
                ((Function1) this.c).invoke(new com.quizlet.login.login.data.e(email, password));
                break;
            case 17:
                ((Integer) obj2).getClass();
                AbstractC3581b0.c((o) this.b, (Function1) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 18:
                ((Integer) obj2).getClass();
                AbstractC3621g0.d((com.quizlet.login.resetpassword.data.g) this.b, (Function1) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 19:
                ((Integer) obj2).getClass();
                AbstractC3625g4.c((r) this.b, (Function1) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 20:
                ((Integer) obj2).getClass();
                AbstractC3594c5.b((InterfaceC4646d) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 21:
                ((Integer) obj2).getClass();
                E5.a((com.quizlet.quizletandroid.ui.onboarding.h) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(49));
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(65);
                ((com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.f) this.b).f((O) this.c, (InterfaceC0806l) obj, iH3);
                break;
            case EventType.AUDIO /* 23 */:
                ((Integer) obj2).getClass();
                AbstractC3627g6.c((com.quizlet.quizletandroid.ui.globalnav.composable.n) this.b, (n) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.VIDEO /* 24 */:
                ((Integer) obj2).getClass();
                AbstractC3635h6.c((M) this.b, (L) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.SUBS /* 25 */:
                ((Integer) obj2).getClass();
                I6.c((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g) this.b, (Function1) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.CDN /* 26 */:
                ((Integer) obj2).getClass();
                Z6.a((m) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 27:
                ((Integer) obj2).getClass();
                b7.a((com.quizlet.quizletandroid.ui.studymodes.testmode.models.p) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 28:
                ((Integer) obj2).getClass();
                d7.a((com.quizlet.assembly.widgets.progress.d) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(9));
                break;
            default:
                ((Integer) obj2).getClass();
                g7.b((C4757a) this.b, (q) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ d(Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.b = obj;
        this.c = obj2;
    }
}
