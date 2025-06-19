package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Handler;
import android.os.Looper;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
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
import com.comscore.streaming.ContentType;
import com.quizlet.assembly.compose.buttons.C4079d;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class S {
    public static final void a(String str, com.quizlet.features.blocks.ui.a aVar, com.quizlet.features.consent.onetrust.d dVar, String str2, String str3, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1269458903);
        int i2 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(aVar) ? 32 : 16) | (c0814p.h(dVar) ? 256 : 128) | (c0814p.f(str2) ? 2048 : 1024) | (c0814p.f(str3) ? 16384 : 8192);
        if ((i & 196608) == 0) {
            i2 |= c0814p.h(function0) ? 131072 : 65536;
        }
        if ((i2 & 74899) == 74898 && c0814p.x()) {
            c0814p.Q();
        } else {
            long jG = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g();
            c0814p.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p).g, new C0416v0(C0380d.e(c0814p).k, AbstractC0382e.g));
            c0814p.p(false);
            AbstractC0725t3.a(null, null, null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(-1401178970, new com.quizlet.features.blocks.ui.d(str, aVar, dVar, str2, str3, function0), c0814p), c0814p, 805306368, 191);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.screens.a(str, aVar, dVar, str2, str3, function0, i);
        }
    }

    public static final void b(com.quizlet.features.blocks.g viewModel, com.quizlet.features.blocks.ui.a gamesJSBridge, com.quizlet.features.consent.onetrust.d consentManager, Function0 onCloseClick, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        Intrinsics.checkNotNullParameter(gamesJSBridge, "gamesJSBridge");
        Intrinsics.checkNotNullParameter(consentManager, "consentManager");
        Intrinsics.checkNotNullParameter(onCloseClick, "onCloseClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1319609241);
        int i2 = (c0814p.h(viewModel) ? 4 : 2) | i | (c0814p.f(gamesJSBridge) ? 32 : 16) | (c0814p.h(consentManager) ? 256 : 128) | (c0814p.h(onCloseClick) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            a(viewModel.b, gamesJSBridge, consentManager, viewModel.c, viewModel.d, onCloseClick, c0814p, (i2 & 1008) | ((i2 << 6) & 458752));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i((Object) viewModel, (Object) gamesJSBridge, (Object) consentManager, onCloseClick, i, 2);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r13v10 */
    /* JADX WARN: Type inference failed for: r13v8 */
    /* JADX WARN: Type inference failed for: r13v9, types: [boolean, int] */
    public static final void c(String str, com.quizlet.features.blocks.ui.a aVar, com.quizlet.features.consent.onetrust.d dVar, String str2, String str3, Function0 function0, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        Object obj;
        InterfaceC0773a0 interfaceC0773a0;
        int i2;
        ?? r13;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-97130434);
        int i3 = i | (c0814p.f(str) ? 4 : 2) | (c0814p.f(aVar) ? 32 : 16) | (c0814p.h(dVar) ? 256 : 128) | (c0814p.f(str2) ? 2048 : 1024) | (c0814p.f(str3) ? 16384 : 8192) | (c0814p.h(function0) ? 131072 : 65536) | (c0814p.f(qVar) ? 1048576 : 524288);
        if ((599187 & i3) == 599186 && c0814p.x()) {
            c0814p.Q();
        } else {
            Pair pair = new Pair("Authorization", AbstractC0147y.d("Bearer ", str3));
            String languageTag = Locale.getDefault().toLanguageTag();
            if (languageTag == null) {
                languageTag = "";
            }
            Map mapF = kotlin.collections.V.f(pair, new Pair("Accept-Language", languageTag));
            c0814p.X(-2037081640);
            Object objI = c0814p.I();
            Object obj2 = C0804k.a;
            if (objI == obj2) {
                objI = C0776c.z(null);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            Object[] objArr = new Object[0];
            c0814p.X(-2037079345);
            Object objI2 = c0814p.I();
            if (objI2 == obj2) {
                objI2 = new com.quizlet.db.data.models.persisted.types.a(27);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI2, c0814p, 3072, 6);
            c0814p.X(-2037077581);
            Object objI3 = c0814p.I();
            if (objI3 == obj2) {
                objI3 = new com.quizlet.features.blocks.ui.f(interfaceC0773a03);
                c0814p.i0(objI3);
            }
            com.quizlet.features.blocks.ui.f fVar = (com.quizlet.features.blocks.ui.f) objI3;
            Object objG = com.google.android.gms.measurement.internal.Z.g(-2037066551, c0814p, false);
            if (objG == obj2) {
                objG = new com.quizlet.features.blocks.ui.e();
                c0814p.i0(objG);
            }
            com.quizlet.features.blocks.ui.e eVar = (com.quizlet.features.blocks.ui.e) objG;
            c0814p.p(false);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.a, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "webViewTag");
            c0814p.X(1468668137);
            boolean zH = ((i3 & 7168) == 2048) | c0814p.h(dVar) | ((i3 & ContentType.LONG_FORM_ON_DEMAND) == 32) | ((i3 & 14) == 4) | c0814p.f(mapF);
            Object objI4 = c0814p.I();
            if (zH || objI4 == obj2) {
                obj = obj2;
                interfaceC0773a0 = interfaceC0773a02;
                i2 = i3;
                r13 = 0;
                com.quizlet.features.blocks.ui.b bVar = new com.quizlet.features.blocks.ui.b(fVar, eVar, str2, dVar, aVar, str, mapF, interfaceC0773a0);
                c0814p.i0(bVar);
                objI4 = bVar;
            } else {
                i2 = i3;
                obj = obj2;
                interfaceC0773a0 = interfaceC0773a02;
                r13 = 0;
            }
            c0814p.p(r13);
            androidx.compose.ui.viewinterop.k.a((Function1) objI4, qVarG, null, c0814p, 48, 4);
            c0814p.X(1468695238);
            if (((Boolean) interfaceC0773a03.getValue()).booleanValue()) {
                AbstractC3249r5.a(null, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.g(), c0814p, 0, 1);
            }
            c0814p.p(r13);
            c0814p.X(1468700053);
            boolean z = (458752 & i2) == 131072 ? true : r13;
            Object objI5 = c0814p.I();
            if (z || objI5 == obj) {
                objI5 = new com.quizlet.features.blocks.ui.c(function0, interfaceC0773a0, 0);
                c0814p.i0(objI5);
            }
            c0814p.p(r13);
            androidx.work.impl.t.a(true, (Function0) objI5, c0814p, 6, r13);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4079d(str, (Object) aVar, (Object) dVar, str2, (Object) str3, (Object) function0, qVar, i, 2);
        }
    }

    public static void d() {
        AbstractC3242q6.h("Not in application's main thread", e());
    }

    public static boolean e() {
        return Looper.getMainLooper().getThread() == Thread.currentThread();
    }

    public static ArrayList f(com.quizlet.remote.mapper.base.a aVar, List remotes) {
        Intrinsics.checkNotNullParameter(remotes, "remotes");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(remotes, 10));
        Iterator it2 = remotes.iterator();
        while (it2.hasNext()) {
            arrayList.add(aVar.c(it2.next()));
        }
        return arrayList;
    }

    public static void g(Runnable runnable) {
        if (e()) {
            runnable.run();
        } else {
            AbstractC3242q6.h("Unable to post to main thread", new Handler(Looper.getMainLooper()).post(runnable));
        }
    }
}
