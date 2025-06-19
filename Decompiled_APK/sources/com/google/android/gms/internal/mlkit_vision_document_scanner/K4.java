package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.os.Bundle;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3153g7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3171i7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.quizlet.features.achievements.ui.composables.C4214a;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.quizlet.upgrade.ui.fragment.UpgradeFragment;
import java.net.URLDecoder;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes2.dex */
public abstract class K4 {
    public static final void a(androidx.compose.ui.n nVar, C4739h c4739h, androidx.navigation.H h, boolean z, com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        int i2;
        com.quizlet.quizletandroid.ui.globalnav.navigation.a aVarB;
        com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1958601848);
        int i3 = i | 6 | (c0814p.h(c4739h) ? 32 : 16) | (c0814p.h(h) ? 256 : 128) | (c0814p.g(z) ? 2048 : 1024) | 8192;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
            aVar2 = aVar;
        } else {
            c0814p.S();
            if ((i & 1) == 0 || c0814p.w()) {
                nVar2 = androidx.compose.ui.n.b;
                c0814p.X(1907377511);
                Object objB = com.google.android.gms.internal.mlkit_vision_barcode.K6.b(com.quizlet.quizletandroid.ui.globalnav.di.a.class, c0814p.j(AndroidCompositionLocals_androidKt.b));
                c0814p.p(false);
                i2 = i3 & (-57345);
                aVarB = ((C4622e) ((com.quizlet.quizletandroid.ui.globalnav.di.a) objB)).b();
            } else {
                c0814p.Q();
                nVar2 = nVar;
                i2 = i3 & (-57345);
                aVarB = aVar;
            }
            c0814p.q();
            GlobalNavSuiteItem$Home globalNavSuiteItem$Home = GlobalNavSuiteItem$Home.INSTANCE;
            c0814p.X(-4386623);
            boolean zH = ((i2 & 7168) == 2048) | c0814p.h(aVarB) | c0814p.h(c4739h);
            Object objI = c0814p.I();
            if (zH || objI == C0804k.a) {
                objI = new com.braze.ui.g(z, aVarB, nVar2, c4739h);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            com.google.android.gms.internal.mlkit_vision_camera.Q1.c(h, globalNavSuiteItem$Home, null, null, null, null, null, null, null, (Function1) objI, c0814p, ((i2 >> 6) & 14) | 48);
            aVar2 = aVarB;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.listitems.b(nVar2, c4739h, h, z, aVar2, i);
        }
    }

    public static final void b(String str, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1608802136);
        if ((((c0814p.f(str) ? 4 : 2) | i | (c0814p.f(qVar) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = qVar.g(androidx.compose.foundation.layout.K0.c);
            Boolean bool = Boolean.FALSE;
            Bundle bundleA = AbstractC3206m6.a(new Pair("isAfterSignUp", bool), new Pair("UpgradeSource", str), new Pair("skipToPlansState", bool), new Pair("fromGlobalNav", Boolean.TRUE));
            c0814p.Y(1765406104);
            AbstractC3153g7.a(UpgradeFragment.class, qVarG, AbstractC3171i7.f(c0814p), bundleA, com.quizlet.quizletandroid.ui.globalnav.composable.t.d, c0814p, 0);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C4214a(str, qVar, i, 6);
        }
    }

    public static com.perimeterx.mobile_sdk.models.d c(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        if (!StringsKt.G(url, "status=", false)) {
            return null;
        }
        try {
            for (Object obj : StringsKt__StringsKt.split$default(url, new String[]{com.perimeterx.mobile_sdk.configurations.l.b.a()}, false, 0, 6, null)) {
                if (kotlin.text.D.r((String) obj, "token=", false)) {
                    String strO = kotlin.text.D.o((String) obj, "token=", "", false);
                    com.perimeterx.mobile_sdk.configurations.d[] dVarArr = com.perimeterx.mobile_sdk.configurations.d.a;
                    if (com.perimeterx.mobile_sdk.configurations.c.a[0] != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    String strDecode = URLDecoder.decode(strO, "UTF-8");
                    Intrinsics.d(strDecode);
                    List listSplit$default = StringsKt__StringsKt.split$default(strDecode, new String[]{"|"}, false, 0, 6, null);
                    if (listSplit$default.size() != 3) {
                        return null;
                    }
                    return new com.perimeterx.mobile_sdk.models.d((String) listSplit$default.get(0), (String) listSplit$default.get(2));
                }
            }
            throw new NoSuchElementException("Collection contains no element matching the predicate.");
        } catch (NoSuchElementException unused) {
            return null;
        }
    }
}
