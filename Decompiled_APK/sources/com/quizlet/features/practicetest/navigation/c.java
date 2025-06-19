package com.quizlet.features.practicetest.navigation;

import android.content.Context;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0839z;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.navigation.B;
import androidx.navigation.H;
import androidx.navigation.W;
import androidx.navigation.r;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.J1;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.U0;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.features.infra.navigation.C;
import com.quizlet.features.infra.navigation.D;
import com.quizlet.features.infra.navigation.m;
import com.quizlet.features.infra.navigation.q;
import com.quizlet.features.infra.navigation.t;
import com.quizlet.features.infra.navigation.w;
import com.quizlet.quizletandroid.C4622e;
import kotlin.Pair;
import kotlin.coroutines.n;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c {
    public static final /* synthetic */ int a = 0;
    public static String b;

    public static final void a(String str, String startDestination, String str2, String str3, H h, d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        H h2;
        d dVar2;
        H h3;
        d dVar3;
        C0814p c0814p;
        H h4;
        d dVar4;
        Intrinsics.checkNotNullParameter(startDestination, "startDestination");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-570266202);
        int i3 = i | (c0814p2.f(str) ? 4 : 2) | (c0814p2.f(startDestination) ? 32 : 16) | (c0814p2.f(str2) ? 256 : 128) | (c0814p2.f(str3) ? 2048 : 1024) | 73728;
        if ((74899 & i3) == 74898 && c0814p2.x()) {
            c0814p2.Q();
            h4 = h;
            dVar4 = dVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                H hD = O1.d(new W[0], c0814p2);
                c0814p2.X(1907377511);
                Object objB = K6.b(com.quizlet.features.practicetest.di.a.class, c0814p2.j(AndroidCompositionLocals_androidKt.b));
                c0814p2.p(false);
                C4622e c4622e = (C4622e) ((com.quizlet.features.practicetest.di.a) objB);
                d dVar5 = new d((C) c4622e.l.get(), (w) c4622e.p.get(), (t) c4622e.w.get(), (D) c4622e.x.get(), (m) c4622e.y.get(), (q) c4622e.z.get());
                i2 = i3 & (-516097);
                h2 = hD;
                dVar2 = dVar5;
            } else {
                c0814p2.Q();
                dVar2 = dVar;
                i2 = i3 & (-516097);
                h2 = h;
            }
            c0814p2.q();
            Context context = (Context) c0814p2.j(AndroidCompositionLocals_androidKt.b);
            c0814p2.X(-395946792);
            Object objI = c0814p2.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new androidx.navigation.compose.w(context, 4);
                c0814p2.i0(objI);
            }
            Function0 function0 = (Function0) objI;
            Object objG = Z.g(-395943448, c0814p2, false);
            if (objG == v) {
                objG = new androidx.work.impl.utils.q(startDestination, h2, str, 20);
                c0814p2.i0(objG);
            }
            Function0 function02 = (Function0) objG;
            c0814p2.p(false);
            Object objI2 = c0814p2.I();
            if (objI2 == v) {
                objI2 = android.support.v4.media.session.a.c(C0776c.n(n.a, c0814p2), c0814p2);
            }
            kotlinx.coroutines.C c = ((C0839z) objI2).a;
            c0814p2.X(-395922856);
            boolean zH = ((i2 & 14) == 4) | c0814p2.h(dVar2) | c0814p2.h(h2) | ((i2 & 896) == 256) | ((i2 & 7168) == 2048) | c0814p2.h(c);
            Object objI3 = c0814p2.I();
            if (zH || objI3 == v) {
                h3 = h2;
                com.quizlet.features.blocks.ui.b bVar = new com.quizlet.features.blocks.ui.b(str, str2, str3, dVar2, function0, h3, function02, c);
                dVar3 = dVar2;
                c0814p2.i0(bVar);
                objI3 = bVar;
            } else {
                h3 = h2;
                dVar3 = dVar2;
            }
            c0814p2.p(false);
            H h5 = h3;
            c0814p = c0814p2;
            Q1.d(h5, startDestination, null, (Function1) objI3, c0814p, i2 & ContentType.LONG_FORM_ON_DEMAND, 12);
            h4 = h5;
            dVar4 = dVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.explanations.questiondetail.ui.composables.e(str, startDestination, str2, str3, h4, dVar4, i, 5);
        }
    }

    public static final void b(H h, String str, String str2) {
        Intrinsics.checkNotNullParameter(h, "<this>");
        B bK = h.b.h().k("practiceTest");
        if (bK != null) {
            h.b(bK.b.c, AbstractC3206m6.a(new Pair("questionBankUuid", str), new Pair("practiceTestSessionId", str2)), J1.c(new a(6)));
        } else {
            h.c("practiceTest", new a(0));
        }
    }

    public static final void c(H h, int i, String modelId) {
        Intrinsics.checkNotNullParameter(h, "<this>");
        Intrinsics.checkNotNullParameter(modelId, "modelId");
        B bK = h.b.h().k("report_content");
        if (bK != null) {
            h.b(bK.b.c, AbstractC3206m6.a(new Pair(DBImageRefFields.Names.MODEL_TYPE, Integer.valueOf(i)), new Pair(DBImageRefFields.Names.MODEL_ID, modelId)), J1.c(new com.quizlet.features.notes.detail.navigation.c(2, bK)));
        } else {
            r.d(h, "report_content");
        }
    }

    public static final void d(H h, String practiceTestId, String practiceTestSessionId) {
        Intrinsics.checkNotNullParameter(h, "<this>");
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        Intrinsics.checkNotNullParameter(practiceTestSessionId, "practiceTestSessionId");
        B bK = h.b.h().k("results");
        if (bK != null) {
            h.b(bK.b.c, AbstractC3206m6.a(new Pair("practiceTestId", practiceTestId), new Pair("practiceTestSessionId", practiceTestSessionId)), J1.c(new a(4)));
        } else {
            h.c("results", new a(5));
        }
    }

    public static final void e(H h, String practiceTestId, String questionBankId, U0 navigationOrigin, String str) {
        Intrinsics.checkNotNullParameter(h, "<this>");
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        Intrinsics.checkNotNullParameter(navigationOrigin, "navigationOrigin");
        androidx.navigation.D dH = h.b.h();
        String str2 = navigationOrigin.a;
        B bK = dH.k("takingTest");
        if (bK != null) {
            h.b(bK.b.c, AbstractC3206m6.a(new Pair("practiceTestId", practiceTestId), new Pair("questionBankUuid", questionBankId), new Pair("navigationOrigin", navigationOrigin.a), new Pair("practiceTestSessionId", str)), J1.c(new a(2)));
        } else {
            h.c("takingTest", new a(3));
        }
    }
}
