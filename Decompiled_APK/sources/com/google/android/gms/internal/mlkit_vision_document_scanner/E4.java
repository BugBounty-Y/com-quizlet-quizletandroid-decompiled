package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.os.Bundle;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.p0;
import androidx.navigation.C1289k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Create;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.H;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.I;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public abstract class E4 {
    public static final void a(androidx.navigation.H navController, com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L legacyHomeNavigationViewModel, C4739h creationMenuViewModel, com.quizlet.quizletandroid.ui.globalnav.navigation.a navigationManager, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        Intrinsics.checkNotNullParameter(navController, "navController");
        Intrinsics.checkNotNullParameter(legacyHomeNavigationViewModel, "legacyHomeNavigationViewModel");
        Intrinsics.checkNotNullParameter(creationMenuViewModel, "creationMenuViewModel");
        Intrinsics.checkNotNullParameter(navigationManager, "navigationManager");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-388729409);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(navController) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(legacyHomeNavigationViewModel) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(creationMenuViewModel) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.h(navigationManager) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function1) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            Object objJ = c0814p.j(androidx.activity.compose.l.a);
            Intrinsics.e(objJ, "null cannot be cast to non-null type androidx.fragment.app.FragmentActivity");
            androidx.fragment.app.I i3 = (androidx.fragment.app.I) objJ;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D(function1, c0814p);
            int i4 = i2 >> 3;
            int i5 = (i2 << 9) & 7168;
            c(i3, legacyHomeNavigationViewModel, navigationManager, navController, (Function1) interfaceC0773a0D.getValue(), c0814p, (i2 & ContentType.LONG_FORM_ON_DEMAND) | (i4 & 896) | i5);
            c0814p = c0814p;
            b(i3, creationMenuViewModel, navigationManager, navController, c0814p, (i4 & 1008) | i5);
            Unit unit = Unit.a;
            c0814p.X(-1165971675);
            boolean zF = c0814p.f(interfaceC0773a0D);
            Object objI = c0814p.I();
            if (zF || objI == v) {
                objI = new com.quizlet.quizletandroid.ui.globalnav.composable.e(interfaceC0773a0D, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(navController, legacyHomeNavigationViewModel, creationMenuViewModel, navigationManager, function1, i, 16);
        }
    }

    public static final void b(androidx.fragment.app.I i, C4739h c4739h, com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar, androidx.navigation.H h, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-67317736);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.h(i) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.h(c4739h) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.h(aVar) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(h) ? 2048 : 1024;
        }
        if ((i3 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            kotlinx.coroutines.flow.Y y = new kotlinx.coroutines.flow.Y(c4739h.j);
            c0814p.X(-782910446);
            boolean zH = c0814p.h(h) | c0814p.h(aVar) | c0814p.h(i);
            Object objI = c0814p.I();
            androidx.compose.runtime.V v = C0804k.a;
            if (zH || objI == v) {
                objI = new com.quizlet.quizletandroid.ui.globalnav.composable.h(h, aVar, i, null);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(j) | c0814p.h(y) | c0814p.f(interfaceC0773a0D);
            Object objI2 = c0814p.I();
            if (zF || objI2 == v) {
                objI2 = new com.quizlet.quizletandroid.ui.globalnav.composable.g(interfaceC0773a0D, j, null, y);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI2);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.quizletandroid.ui.globalnav.composable.d(i, c4739h, aVar, h, i2, 0);
        }
    }

    public static final void c(androidx.fragment.app.I i, final com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L l, com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar, androidx.navigation.H h, Function1 function1, InterfaceC0806l interfaceC0806l, int i2) {
        int i3;
        androidx.fragment.app.I i4 = i;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1842242708);
        if ((i2 & 6) == 0) {
            i3 = (c0814p.h(i4) ? 4 : 2) | i2;
        } else {
            i3 = i2;
        }
        if ((i2 & 48) == 0) {
            i3 |= c0814p.h(l) ? 32 : 16;
        }
        if ((i2 & 384) == 0) {
            i3 |= c0814p.h(aVar) ? 256 : 128;
        }
        if ((i2 & 3072) == 0) {
            i3 |= c0814p.h(h) ? 2048 : 1024;
        }
        if ((i2 & 24576) == 0) {
            i3 |= c0814p.h(function1) ? 16384 : 8192;
        }
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.activity.result.contract.b bVar = new androidx.activity.result.contract.b(4);
            c0814p.X(-363752847);
            boolean zH = ((i3 & 57344) == 16384) | c0814p.h(h) | c0814p.h(l);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new androidx.lifecycle.compose.d(h, function1, l, 22);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            androidx.activity.compose.o oVarF = androidx.work.P.f(bVar, (Function1) objI, c0814p);
            androidx.activity.result.contract.b bVar2 = new androidx.activity.result.contract.b(4);
            c0814p.X(-363739478);
            boolean zH2 = c0814p.h(aVar);
            Object objI2 = c0814p.I();
            if (zH2 || objI2 == v) {
                objI2 = new com.quizlet.quizletandroid.ui.common.ads.G(aVar, 7);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            androidx.activity.compose.o oVarF2 = androidx.work.P.f(bVar2, (Function1) objI2, c0814p);
            i4.getSupportFragmentManager().h0("createFolderRequestKey", i4, new com.quizlet.infra.legacysyncengine.tasks.parse.b(aVar, 4));
            i4.getSupportFragmentManager().h0("UpgradeFragmentRequestKey", i4, new com.google.firebase.tracing.a(25, h, function1));
            final int i5 = 1;
            i4.getSupportFragmentManager().h0("freeTrialConfirmationRequest", i4, new androidx.fragment.app.m0() { // from class: com.quizlet.quizletandroid.ui.globalnav.composable.c
                @Override // androidx.fragment.app.m0
                public final void y(Bundle result, String requestKey) {
                    switch (i5) {
                        case 0:
                            Intrinsics.checkNotNullParameter(requestKey, "requestKey");
                            Intrinsics.checkNotNullParameter(result, "result");
                            boolean z = result.getBoolean("creatorMarketingCreateClicked");
                            L l2 = l;
                            if (!z) {
                                l2.s.j(H.a);
                                break;
                            } else {
                                l2.getClass();
                                E.A(p0.j(l2), null, null, new I(l2, null), 3);
                                break;
                            }
                        default:
                            Intrinsics.checkNotNullParameter(requestKey, "requestKey");
                            Intrinsics.checkNotNullParameter(result, "<unused var>");
                            if (requestKey.hashCode() == 2070037552 && requestKey.equals("freeTrialConfirmationRequest")) {
                                L l3 = l;
                                l3.getClass();
                                E.A(p0.j(l3), null, null, new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.E(l3, null), 3);
                                break;
                            }
                            break;
                    }
                }
            });
            i4.getSupportFragmentManager().h0("onboardingELLRequestKey", i4, new androidx.camera.camera2.internal.T(h, function1, l, 25));
            final int i6 = 0;
            i4.getSupportFragmentManager().h0("creatorMarketingRequestKey", i4, new androidx.fragment.app.m0() { // from class: com.quizlet.quizletandroid.ui.globalnav.composable.c
                @Override // androidx.fragment.app.m0
                public final void y(Bundle result, String requestKey) {
                    switch (i6) {
                        case 0:
                            Intrinsics.checkNotNullParameter(requestKey, "requestKey");
                            Intrinsics.checkNotNullParameter(result, "result");
                            boolean z = result.getBoolean("creatorMarketingCreateClicked");
                            L l2 = l;
                            if (!z) {
                                l2.s.j(H.a);
                                break;
                            } else {
                                l2.getClass();
                                E.A(p0.j(l2), null, null, new I(l2, null), 3);
                                break;
                            }
                        default:
                            Intrinsics.checkNotNullParameter(requestKey, "requestKey");
                            Intrinsics.checkNotNullParameter(result, "<unused var>");
                            if (requestKey.hashCode() == 2070037552 && requestKey.equals("freeTrialConfirmationRequest")) {
                                L l3 = l;
                                l3.getClass();
                                E.A(p0.j(l3), null, null, new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.E(l3, null), 3);
                                break;
                            }
                            break;
                    }
                }
            });
            kotlinx.coroutines.flow.d0 d0Var = l.p;
            c0814p.X(-363720507);
            boolean zH3 = c0814p.h(h) | c0814p.h(aVar) | c0814p.h(i4) | c0814p.h(oVarF) | c0814p.h(oVarF2);
            Object objI3 = c0814p.I();
            if (zH3 || objI3 == v) {
                com.quizlet.quizletandroid.ui.globalnav.composable.m mVar = new com.quizlet.quizletandroid.ui.globalnav.composable.m(h, aVar, i4, oVarF, oVarF2, null);
                i4 = i4;
                c0814p.i0(mVar);
                objI3 = mVar;
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            androidx.lifecycle.J j = (androidx.lifecycle.J) c0814p.j(androidx.lifecycle.compose.g.a);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            InterfaceC0773a0 interfaceC0773a0D = C0776c.D((Function2) objI3, c0814p);
            Unit unit = Unit.a;
            c0814p.X(1667431386);
            boolean zH4 = c0814p.h(j) | c0814p.h(d0Var) | c0814p.f(b) | c0814p.f(interfaceC0773a0D);
            Object objI4 = c0814p.I();
            if (zH4 || objI4 == v) {
                objI4 = new com.quizlet.quizletandroid.ui.globalnav.composable.j(interfaceC0773a0D, j, null, d0Var);
                c0814p.i0(objI4);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI4);
            c0814p.p(false);
            kotlinx.coroutines.flow.d0 d0Var2 = l.q;
            c0814p.X(-363706735);
            boolean zH5 = c0814p.h(aVar) | c0814p.h(i4) | c0814p.h(l);
            Object objI5 = c0814p.I();
            if (zH5 || objI5 == v) {
                objI5 = new com.quizlet.quizletandroid.ui.globalnav.composable.o(aVar, i4, l, null);
                c0814p.i0(objI5);
            }
            c0814p.p(false);
            c0814p.X(-827048655);
            InterfaceC0773a0 interfaceC0773a0D2 = C0776c.D((Function2) objI5, c0814p);
            c0814p.X(1667431386);
            boolean zF = c0814p.f(b) | c0814p.h(i4) | c0814p.h(d0Var2) | c0814p.f(interfaceC0773a0D2);
            Object objI6 = c0814p.I();
            if (zF || objI6 == v) {
                objI6 = new com.quizlet.quizletandroid.ui.globalnav.composable.l(interfaceC0773a0D2, i4, null, d0Var2);
                c0814p.i0(objI6);
            }
            c0814p.p(false);
            C0776c.f(c0814p, unit, (Function2) objI6);
            c0814p.p(false);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.achievements.ui.composables.p(i4, l, aVar, h, function1, i2, 17);
        }
    }

    public static void d(File file, String str) throws Exception {
        String canonicalPath = new File(str).getCanonicalPath();
        String canonicalPath2 = file.getCanonicalPath();
        Intrinsics.d(canonicalPath2);
        Intrinsics.d(canonicalPath);
        if (kotlin.text.D.r(canonicalPath2, canonicalPath, false)) {
            return;
        }
        throw new Exception(String.format("found zip path traversal vulnerability with " + file.getCanonicalPath(), new Object[0]));
    }

    public static void e(InputStream inputStream, String str) throws IOException {
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(str));
        byte[] bArr = new byte[4096];
        while (true) {
            int i = inputStream.read(bArr);
            if (i == -1) {
                bufferedOutputStream.close();
                return;
            }
            bufferedOutputStream.write(bArr, 0, i);
        }
    }

    public static void f(File zipFilePath, String destDirectory) {
        Intrinsics.checkNotNullParameter(zipFilePath, "zipFilePath");
        Intrinsics.checkNotNullParameter(destDirectory, "destDirectory");
        File file = new File(destDirectory);
        if (!file.exists()) {
            file.mkdirs();
        }
        Unit unit = Unit.a;
        ZipFile zipFile = new ZipFile(zipFilePath);
        try {
            Enumeration<? extends ZipEntry> enumerationEntries = zipFile.entries();
            Intrinsics.checkNotNullExpressionValue(enumerationEntries, "entries(...)");
            Intrinsics.checkNotNullParameter(enumerationEntries, "<this>");
            Iterator it2 = kotlin.sequences.n.b(new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.h(enumerationEntries)).iterator();
            while (it2.hasNext()) {
                ZipEntry zipEntry = (ZipEntry) it2.next();
                InputStream inputStream = zipFile.getInputStream(zipEntry);
                try {
                    String str = destDirectory + File.separator + zipEntry.getName();
                    if (zipEntry.isDirectory()) {
                        new File(str).mkdir();
                    } else if (!StringsKt.G(str, "__MACOSX", false)) {
                        try {
                            d(new File(str), destDirectory);
                            Intrinsics.d(inputStream);
                            e(inputStream, str);
                        } catch (Exception unused) {
                        }
                    }
                    Unit unit2 = Unit.a;
                    AbstractC3336f.c(inputStream, null);
                } finally {
                }
            }
            Unit unit3 = Unit.a;
            zipFile.close();
        } finally {
        }
    }

    public static final void g(androidx.navigation.r rVar, com.quizlet.quizletandroid.ui.globalnav.data.k route) {
        Intrinsics.checkNotNullParameter(rVar, "<this>");
        Intrinsics.checkNotNullParameter(route, "destination");
        if (route instanceof GlobalNavSuiteItem$Create) {
            ((GlobalNavSuiteItem$Create) route).getClass();
            rVar.c("Create", new com.quizlet.features.setpage.header.ui.g(12, route, rVar));
            return;
        }
        com.quizlet.features.setpage.header.ui.g builder = new com.quizlet.features.setpage.header.ui.g(12, route, rVar);
        rVar.getClass();
        Intrinsics.checkNotNullParameter(route, "route");
        Intrinsics.checkNotNullParameter(builder, "builder");
        androidx.navigation.internal.j jVar = rVar.b;
        jVar.getClass();
        Intrinsics.checkNotNullParameter(route, "route");
        Intrinsics.checkNotNullParameter(builder, "builder");
        androidx.navigation.K kC = com.google.android.gms.internal.mlkit_vision_camera.J1.c(builder);
        Intrinsics.checkNotNullParameter(route, "route");
        jVar.getClass();
        Intrinsics.checkNotNullParameter(route, "route");
        androidx.navigation.B bE = androidx.navigation.internal.j.e(androidx.navigation.serialization.d.b(com.google.android.gms.internal.mlkit_vision_camera.P1.e(kotlin.jvm.internal.K.a(route.getClass()))), jVar.h(), null, true);
        if (bE == null) {
            throw new IllegalArgumentException(("Destination with route " + kotlin.jvm.internal.K.a(route.getClass()).f() + " cannot be found in navigation graph " + jVar.c).toString());
        }
        Map mapH = bE.h();
        LinkedHashMap linkedHashMap = new LinkedHashMap(kotlin.collections.U.a(mapH.size()));
        for (Map.Entry entry : mapH.entrySet()) {
            linkedHashMap.put(entry.getKey(), ((C1289k) entry.getValue()).a);
        }
        jVar.m(androidx.navigation.serialization.d.c(route, linkedHashMap), kC);
    }

    public static final void h(androidx.navigation.H h, Function1 function1) {
        androidx.navigation.B bG = h.b.g();
        if (bG != null) {
            int i = androidx.navigation.B.e;
            C4950i route = kotlin.jvm.internal.K.a(GlobalNavSuiteItem$Home.class);
            Intrinsics.checkNotNullParameter(bG, "<this>");
            Intrinsics.checkNotNullParameter(route, "route");
            if (androidx.navigation.serialization.d.b(com.google.android.gms.internal.mlkit_vision_camera.P1.e(route)) == bG.b.c) {
                function1.invoke(new com.quizlet.quizletandroid.ui.globalnav.data.n(GlobalNavSuiteItem$Home.INSTANCE));
                return;
            }
        }
        g(h, GlobalNavSuiteItem$Home.INSTANCE);
    }
}
