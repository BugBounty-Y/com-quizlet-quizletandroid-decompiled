package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Create;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$FreeTrial;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Upgrade;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$YourLibrary;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class L4 {
    public static com.perimeterx.mobile_sdk.session.l a;
    public static com.perimeterx.mobile_sdk.session.l b;

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00ac  */
    /* JADX WARN: Type inference failed for: r1v0 */
    /* JADX WARN: Type inference failed for: r1v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r1v6 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.foundation.layout.H0 r44, kotlinx.collections.immutable.b r45, androidx.navigation.B r46, kotlin.jvm.functions.Function1 r47, androidx.compose.runtime.InterfaceC0806l r48, int r49) {
        /*
            Method dump skipped, instructions count: 436
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.L4.a(androidx.compose.foundation.layout.H0, kotlinx.collections.immutable.b, androidx.navigation.B, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int):void");
    }

    public static final void b(com.quizlet.quizletandroid.ui.globalnav.data.k kVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.graphics.painter.b bVarD;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-11087831);
        if ((((c0814p.f(kVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.g();
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.h);
            Intrinsics.checkNotNullParameter(kVar, "<this>");
            c0814p.X(8056425);
            if (Intrinsics.b(kVar, GlobalNavSuiteItem$Home.INSTANCE)) {
                c0814p.X(594321535);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                c0814p.X(87617006);
                bVarD = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_home, c0814p, 0, false, false);
            } else if (Intrinsics.b(kVar, GlobalNavSuiteItem$Create.INSTANCE)) {
                c0814p.X(594323743);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                bVarD = com.quizlet.ui.resources.icons.d.F(c0814p);
                c0814p.p(false);
            } else if (kVar instanceof GlobalNavSuiteItem$YourLibrary) {
                c0814p.X(594326210);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).a.getClass();
                c0814p.X(1335268084);
                bVarD = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_sys_library, c0814p, 0, false, false);
            } else {
                if (!(kVar instanceof GlobalNavSuiteItem$FreeTrial) && !(kVar instanceof GlobalNavSuiteItem$Upgrade)) {
                    throw com.google.android.gms.measurement.internal.Z.j(594319481, c0814p, false);
                }
                c0814p.X(594330914);
                ((com.quizlet.themes.d) c0814p.j(com.quizlet.themes.e.a)).e.getClass();
                c0814p.X(405608082);
                bVarD = com.google.android.gms.measurement.internal.Z.d(R.drawable.ic_comp_global_nav_upgrade, c0814p, 0, false, false);
            }
            c0814p.p(false);
            androidx.compose.material3.D1.a(bVarD, AbstractC3106b5.d(c0814p, kVar.a), qVarK, 0L, c0814p, 0, 8);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.w(kVar, i, 0);
        }
    }

    public static final void c(com.quizlet.quizletandroid.ui.globalnav.data.k kVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1462338470);
        if ((((c0814p2.f(kVar) ? 4 : 2) | i) & 3) == 2 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p = c0814p2;
            androidx.compose.material3.Q4.b(AbstractC3106b5.d(c0814p2, kVar.a), null, 0L, 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.a)).l, c0814p, 0, 0, 65534);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.w(kVar, i, 1);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0091  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static kotlin.Pair d(okhttp3.C r7, okhttp3.t r8) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 257
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.L4.d(okhttp3.C, okhttp3.t):kotlin.Pair");
    }
}
