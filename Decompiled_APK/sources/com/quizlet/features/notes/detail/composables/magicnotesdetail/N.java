package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.foundation.pager.C0466e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.u7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.google.android.gms.internal.mlkit_vision_camera.S2;
import com.google.android.gms.internal.mlkit_vision_camera.Z2;
import com.google.android.gms.internal.mlkit_vision_camera.t3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3467i;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3503o;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3507o3;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import com.google.android.gms.internal.mlkit_vision_common.H2;
import com.google.android.gms.internal.mlkit_vision_common.I2;
import com.google.android.gms.internal.mlkit_vision_common.L2;
import com.google.android.gms.internal.mlkit_vision_common.P2;
import com.google.android.gms.internal.mlkit_vision_common.P3;
import com.google.android.gms.internal.mlkit_vision_common.R2;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3594c5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3621g0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3768y4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z5;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.m2;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.features.universaluploadflow.data.C4458g;
import com.quizlet.quizletandroid.ui.library.data.C4647a;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class N implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ N(int i, int i2, androidx.compose.ui.q qVar, Object obj, Object obj2) {
        this.a = i2;
        this.b = obj;
        this.d = qVar;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                int iH = C0776c.H(1);
                u7.b((NotesToValueInfo) this.b, (Function0) this.c, (androidx.compose.ui.q) this.d, interfaceC0806l, iH);
                break;
            case 1:
                int iH2 = C0776c.H(1);
                AbstractC3409x1.d((com.quizlet.features.onboarding.ell.x) this.b, (Function1) this.c, (androidx.compose.ui.n) this.d, interfaceC0806l, iH2);
                break;
            case 2:
                K1.c((com.quizlet.features.paywall.state.c) this.b, (Function0) this.c, (Function0) this.d, interfaceC0806l, C0776c.H(1));
                break;
            case 3:
                AbstractC3390s2.a((com.quizlet.features.practicetest.takingtest.data.G) this.b, (Function0) this.c, (androidx.compose.ui.q) this.d, interfaceC0806l, C0776c.H(1));
                break;
            case 4:
                int iH3 = C0776c.H(1);
                S2.d((Function1) this.b, (Function1) this.c, (androidx.compose.ui.q) this.d, interfaceC0806l, iH3);
                break;
            case 5:
                int iH4 = C0776c.H(1);
                com.quizlet.features.questiontypes.fitb.ui.l.c((com.quizlet.features.questiontypes.basequestion.i) this.b, (androidx.compose.ui.q) this.d, (com.quizlet.features.questiontypes.fitb.m) this.c, interfaceC0806l, iH4);
                break;
            case 6:
                int iH5 = C0776c.H(1);
                Z2.a((com.quizlet.features.questiontypes.basequestion.i) this.b, (androidx.compose.ui.q) this.d, (com.quizlet.features.questiontypes.mcq.a) this.c, interfaceC0806l, iH5);
                break;
            case 7:
                t3.a((com.quizlet.features.questiontypes.truefalse.d) this.b, (Function0) this.c, (Function0) this.d, interfaceC0806l, C0776c.H(7));
                break;
            case 8:
                int iH6 = C0776c.H(1);
                t3.d((com.quizlet.features.questiontypes.basequestion.i) this.b, (androidx.compose.ui.q) this.d, (com.quizlet.features.questiontypes.truefalse.b) this.c, interfaceC0806l, iH6);
                break;
            case 9:
                int iH7 = C0776c.H(1);
                AbstractC3467i.e((com.quizlet.features.questiontypes.basequestion.i) this.b, (androidx.compose.ui.q) this.d, (com.quizlet.features.questiontypes.written.a) this.c, interfaceC0806l, iH7);
                break;
            case 10:
                int iH8 = C0776c.H(7);
                AbstractC3467i.c((com.quizlet.features.questiontypes.written.data.f) this.b, (Function2) this.c, (kotlin.jvm.functions.c) this.d, interfaceC0806l, iH8);
                break;
            case 11:
                int iH9 = C0776c.H(1);
                AbstractC3503o.c((Function0) this.c, (P) this.b, (androidx.compose.ui.n) this.d, interfaceC0806l, iH9);
                break;
            case 12:
                int iH10 = C0776c.H(1);
                G2.b((com.quizlet.features.settings.data.states.y) this.b, (com.quizlet.features.settings.composables.j) this.c, (androidx.compose.ui.q) this.d, interfaceC0806l, iH10);
                break;
            case 13:
                int iH11 = C0776c.H(1);
                H2.d((com.quizlet.features.settings.data.states.y) this.b, (androidx.compose.ui.q) this.d, (C1608n) this.c, interfaceC0806l, iH11);
                break;
            case 14:
                int iH12 = C0776c.H(1);
                I2.c((com.quizlet.features.settings.data.states.y) this.b, (com.quizlet.features.settings.composables.n) this.c, (androidx.compose.ui.q) this.d, interfaceC0806l, iH12);
                break;
            case 15:
                int iH13 = C0776c.H(1);
                L2.g((com.quizlet.features.settings.data.states.y) this.b, (Function0) this.c, (Function0) this.d, interfaceC0806l, iH13);
                break;
            case 16:
                int iH14 = C0776c.H(1);
                P2.c((com.quizlet.features.settings.data.states.y) this.b, (androidx.compose.ui.n) this.d, (Function0) this.c, interfaceC0806l, iH14);
                break;
            case 17:
                int iH15 = C0776c.H(1);
                R2.b((com.quizlet.themes.nighttheme.a) this.b, (Function0) this.c, (Function1) this.d, interfaceC0806l, iH15);
                break;
            case 18:
                int iH16 = C0776c.H(1);
                AbstractC3507o3.a((String) this.b, (Function0) this.c, (Function0) this.d, interfaceC0806l, iH16);
                break;
            case 19:
                P3.a(C0776c.H(49), interfaceC0806l, (m2) this.d, (Function0) this.c, (Function0) this.b);
                break;
            case 20:
                int iH17 = C0776c.H(1);
                S3.a((m2) this.b, (C4458g) this.c, (Function1) this.d, interfaceC0806l, iH17);
                break;
            case 21:
                com.quizlet.features.universaluploadflow.navigation.c.e((m2) this.b, (androidx.navigation.H) this.c, (com.quizlet.features.universaluploadflow.navigation.e) this.d, interfaceC0806l, C0776c.H(1));
                break;
            case EventType.WINDOW_STATE /* 22 */:
                int iH18 = C0776c.H(1);
                com.google.android.gms.internal.mlkit_vision_document_scanner.P.e((com.quizlet.login.login.data.w) this.b, (androidx.compose.ui.q) this.d, (Function1) this.c, interfaceC0806l, iH18);
                break;
            case EventType.AUDIO /* 23 */:
                int iH19 = C0776c.H(1);
                T.b((Function0) this.c, (Function1) this.b, (com.quizlet.login.magiclink.viewmodel.b) this.d, interfaceC0806l, iH19);
                break;
            case EventType.VIDEO /* 24 */:
                int iH20 = C0776c.H(1);
                T.a((Function1) this.b, (androidx.compose.ui.q) this.d, (com.quizlet.login.magiclink.data.g) this.c, interfaceC0806l, iH20);
                break;
            case EventType.SUBS /* 25 */:
                int iH21 = C0776c.H(1);
                AbstractC3621g0.c((Function0) this.c, (Function1) this.b, (com.quizlet.login.resetpassword.viewmodel.a) this.d, interfaceC0806l, iH21);
                break;
            case EventType.CDN /* 26 */:
                AbstractC3768y4.a((C4647a) this.b, (androidx.compose.ui.n) this.c, (Function1) this.d, interfaceC0806l, C0776c.H(1));
                break;
            case 27:
                int iH22 = C0776c.H(9);
                AbstractC3594c5.c((kotlinx.collections.immutable.b) this.b, (C0466e) this.c, (androidx.compose.ui.q) this.d, interfaceC0806l, iH22);
                break;
            case 28:
                int iH23 = C0776c.H(1);
                Z5.a((kotlinx.collections.immutable.b) this.b, (com.quizlet.quizletandroid.ui.globalnav.composable.s) this.c, (androidx.compose.ui.n) this.d, interfaceC0806l, iH23);
                break;
            default:
                int iH24 = C0776c.H(1);
                Z5.b((com.quizlet.ui.models.content.home.f) this.b, (androidx.compose.ui.n) this.d, (Function0) this.c, interfaceC0806l, iH24);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ N(int i, int i2, Object obj, Object obj2, Object obj3) {
        this.a = i2;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public /* synthetic */ N(Function0 function0, Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.c = function0;
        this.b = obj;
        this.d = obj2;
    }
}
