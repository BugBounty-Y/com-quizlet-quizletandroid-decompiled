package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.InterfaceC1261w;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3405w1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3417z1;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.data.model.AbstractC4178x;
import java.util.WeakHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes2.dex */
public abstract class T {
    /* JADX WARN: Removed duplicated region for block: B:39:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x014f  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0158  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x015c  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0196  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x019a  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x01b5  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x030c  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x032b  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x032d  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0340  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x03d3  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x03d5  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x03e8  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x041e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(kotlin.jvm.functions.Function1 r41, androidx.compose.ui.q r42, com.quizlet.login.magiclink.data.g r43, androidx.compose.runtime.InterfaceC0806l r44, int r45) {
        /*
            Method dump skipped, instructions count: 1096
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.T.a(kotlin.jvm.functions.Function1, androidx.compose.ui.q, com.quizlet.login.magiclink.data.g, androidx.compose.runtime.l, int):void");
    }

    public static final void b(Function0 onNavigateBack, Function1 onNavigateToEmailSent, com.quizlet.login.magiclink.viewmodel.b bVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        com.quizlet.login.magiclink.viewmodel.b bVar2;
        com.quizlet.login.magiclink.viewmodel.b bVar3;
        Intrinsics.checkNotNullParameter(onNavigateBack, "onNavigateBack");
        Intrinsics.checkNotNullParameter(onNavigateToEmailSent, "onNavigateToEmailSent");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-924095968);
        int i3 = i | (c0814p.h(onNavigateBack) ? 4 : 2) | (c0814p.h(onNavigateToEmailSent) ? 32 : 16) | 128;
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
                Object objE = AbstractC3417z1.e(com.quizlet.login.magiclink.viewmodel.j.class, c0A, null, fVarC, c0A instanceof InterfaceC1261w ? ((InterfaceC1261w) c0A).getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b, c0814p);
                c0814p.p(false);
                c0814p.p(false);
                i2 = i3 & (-897);
                bVar2 = (com.quizlet.login.magiclink.viewmodel.b) objE;
            } else {
                c0814p.Q();
                i2 = i3 & (-897);
                bVar2 = bVar;
            }
            c0814p.q();
            com.quizlet.login.magiclink.viewmodel.j jVar = (com.quizlet.login.magiclink.viewmodel.j) bVar2;
            InterfaceC0773a0 interfaceC0773a0G = AbstractC3409x1.g(jVar.d, c0814p);
            kotlinx.coroutines.flow.d0 d0Var = jVar.e;
            c0814p.X(-1482910587);
            boolean z = (i2 & ContentType.LONG_FORM_ON_DEMAND) == 32;
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (z || objI == v) {
                objI = new com.quizlet.login.magiclink.ui.d(onNavigateToEmailSent, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.login.magiclink.ui.c(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            com.quizlet.login.magiclink.data.k kVar = (com.quizlet.login.magiclink.data.k) AbstractC4178x.k(unit, (Function2) objI2, c0814p, false, interfaceC0773a0G);
            c0814p.X(-1482903697);
            boolean zH = c0814p.h(bVar2);
            Object objI3 = c0814p.I();
            if (zH || objI3 == v) {
                com.quizlet.login.common.navigation.d dVar = new com.quizlet.login.common.navigation.d(1, bVar2, com.quizlet.login.magiclink.viewmodel.b.class, "onSendMagicLink", "onSendMagicLink(Ljava/lang/String;)V", 0, 9);
                c0814p.i0(dVar);
                objI3 = dVar;
            }
            c0814p.p(false);
            c(kVar, onNavigateBack, (Function1) ((kotlin.reflect.f) objI3), c0814p, (i2 << 3) & ContentType.LONG_FORM_ON_DEMAND);
            bVar3 = bVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.notes.detail.composables.magicnotesdetail.N(onNavigateBack, onNavigateToEmailSent, bVar3, i, 23);
        }
    }

    public static final void c(com.quizlet.login.magiclink.data.k kVar, Function0 function0, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(2127843440);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(kVar) : c0814p2.h(kVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function1) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.ui.n.b, "invalidMagicLinkScreen");
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            AbstractC0725t3.a(qVarG, androidx.compose.runtime.internal.e.e(-550793940, new com.quizlet.explanations.questiondetail.ui.composables.m(25, function0), c0814p2), null, null, null, 0, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, c0374a, androidx.compose.runtime.internal.e.e(-1954054015, new com.quizlet.features.questiontypes.mcq.ui.c(9, kVar, function1), c0814p2), c0814p, 805306422, 188);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.questiontypes.selfassessment.ui.a(i, 16, kVar, function0, function1);
        }
    }

    public static void d(JSONException jSONException, StringBuilder sb, String str, int i) {
        sb.append(jSONException.getMessage());
        OTLogger.c(str, i, sb.toString());
    }
}
