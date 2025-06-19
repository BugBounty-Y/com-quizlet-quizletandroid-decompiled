package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation;

import android.content.Context;
import android.content.res.Resources;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.glance.j;
import androidx.navigation.H;
import androidx.navigation.W;
import androidx.navigation.compose.y;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.ui.startpage.nav2.composables.f;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsIntentData;
import java.util.Arrays;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b {
    public static final /* synthetic */ int a = 0;

    public static final void a(LearnSettingsIntentData learnSettingsIntentData, H h, com.quizlet.quizletandroid.ui.navigationmanagers.c cVar, InterfaceC0806l interfaceC0806l, int i) {
        H h2;
        Object eVar;
        H h3;
        Intrinsics.checkNotNullParameter(learnSettingsIntentData, "learnSettingsIntentData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-384329712);
        if ((((c0814p.h(learnSettingsIntentData) ? 4 : 2) | i | 144) & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            h3 = h;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                h = O1.d(new W[0], c0814p);
                c0814p.X(1907377511);
                Object objB = K6.b(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.di.a.class, c0814p.j(AndroidCompositionLocals_androidKt.b));
                c0814p.p(false);
                cVar = (com.quizlet.quizletandroid.ui.navigationmanagers.c) ((C4622e) ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.di.a) objB)).V.get();
            } else {
                c0814p.Q();
            }
            H h4 = h;
            com.quizlet.quizletandroid.ui.navigationmanagers.c cVar2 = cVar;
            c0814p.q();
            Context context = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
            c0814p.X(1419676723);
            Object objI = c0814p.I();
            V v = C0804k.a;
            if (objI == v) {
                objI = new y(context, 1);
                c0814p.i0(objI);
            }
            Function1 function1 = (Function1) objI;
            c0814p.p(false);
            c0814p.X(1419690492);
            boolean zH = c0814p.h(learnSettingsIntentData) | c0814p.h(h4) | c0814p.h(cVar2);
            Object objI2 = c0814p.I();
            if (zH || objI2 == v) {
                h2 = h4;
                eVar = new androidx.navigation.internal.e(learnSettingsIntentData, function1, h2, cVar2, 7);
                cVar = cVar2;
                c0814p.i0(eVar);
            } else {
                h2 = h4;
                eVar = objI2;
                cVar = cVar2;
            }
            Function1 function12 = (Function1) eVar;
            c0814p.p(false);
            H h5 = h2;
            Q1.a(h5, null, null, null, null, null, null, function12, c0814p, 48);
            h3 = h5;
        }
        com.quizlet.quizletandroid.ui.navigationmanagers.c cVar3 = cVar;
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new f(i, 5, learnSettingsIntentData, h3, cVar3);
        }
    }

    public static final androidx.glance.color.a b(B b, InterfaceC0806l interfaceC0806l) {
        Intrinsics.checkNotNullParameter(b, "<this>");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1774271478);
        androidx.compose.runtime.B b2 = com.quizlet.quizletandroid.ui.widgets.ui.theme.a.a;
        androidx.glance.color.a aVar = new androidx.glance.color.a(((C0861v) b.get(((com.quizlet.quizletandroid.ui.widgets.ui.theme.b) c0814p.j(b2)).a)).a, ((C0861v) b.get(((com.quizlet.quizletandroid.ui.widgets.ui.theme.b) c0814p.j(b2)).b)).a);
        c0814p.p(false);
        return aVar;
    }

    public static final String c(int i, int i2, Object[] args, C0814p c0814p) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(args, "args");
        c0814p.X(-775740463);
        String quantityString = ((Context) c0814p.j(j.b)).getResources().getQuantityString(i, i2, Arrays.copyOf(args, args.length));
        Intrinsics.checkNotNullExpressionValue(quantityString, "getQuantityString(...)");
        c0814p.p(false);
        return quantityString;
    }

    public static final String d(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1050225667);
        String string = ((Context) c0814p.j(j.b)).getString(i);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        c0814p.p(false);
        return string;
    }
}
