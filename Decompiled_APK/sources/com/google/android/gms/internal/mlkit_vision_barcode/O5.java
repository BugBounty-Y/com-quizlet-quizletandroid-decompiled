package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.C0374a;
import androidx.compose.foundation.layout.C0380d;
import androidx.compose.foundation.layout.C0416v0;
import androidx.compose.material3.AbstractC0725t3;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.quizletandroid.R;
import java.util.WeakHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class O5 {
    public static final void a(androidx.compose.ui.n nVar, androidx.compose.ui.text.input.A a, kotlinx.collections.immutable.b bVar, boolean z, boolean z2, boolean z3, com.quizlet.features.infra.folder.create.data.b bVar2, com.quizlet.features.infra.folder.create.coursefolder.data.m mVar, Function1 function1, Function1 function12, Function1 function13, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function1 function14, Function0 function05, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        C0814p c0814p;
        androidx.compose.ui.n nVar3;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(618698840);
        int i2 = i | 6 | (c0814p2.f(a) ? 32 : 16) | (c0814p2.h(bVar) ? 256 : 128) | (c0814p2.g(z) ? 2048 : 1024) | (c0814p2.g(z2) ? 16384 : 8192) | (c0814p2.g(z3) ? 131072 : 65536) | (c0814p2.f(bVar2) ? 1048576 : 524288) | (c0814p2.f(mVar) ? 8388608 : 4194304) | (c0814p2.h(function1) ? 67108864 : 33554432) | (c0814p2.h(function12) ? 536870912 : 268435456);
        int i3 = (c0814p2.h(function13) ? (char) 4 : (char) 2) | (c0814p2.h(function0) ? ' ' : (char) 16) | (c0814p2.h(function02) ? 256 : 128) | (c0814p2.h(function03) ? 2048 : 1024) | (c0814p2.h(function04) ? 16384 : 8192) | (c0814p2.h(function14) ? (char) 0 : (char) 0) | (c0814p2.h(function05) ? (char) 0 : (char) 0);
        if ((i2 & 306783379) == 306783378 && (i3 & 599187) == 599186 && c0814p2.x()) {
            c0814p2.Q();
            nVar3 = nVar;
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) == 0 || c0814p2.w()) {
                nVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p2.Q();
                nVar2 = nVar;
            }
            c0814p2.q();
            String strB = b(bVar2, c0814p2);
            String strC = c(bVar2, c0814p2);
            long jG = ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g();
            c0814p2.X(360309978);
            WeakHashMap weakHashMap = androidx.compose.foundation.layout.S0.w;
            C0374a c0374a = new C0374a(C0380d.e(c0814p2).g, new C0416v0(C0380d.e(c0814p2).k, AbstractC0382e.g));
            c0814p2.p(false);
            c0814p = c0814p2;
            androidx.compose.ui.n nVar4 = nVar2;
            AbstractC0725t3.a(nVar4, androidx.compose.runtime.internal.e.e(1378060572, new com.quizlet.features.infra.basestudy.ui.i(strB, function02, strC, function0, z3), c0814p2), null, null, null, 0, jG, 0L, c0374a, androidx.compose.runtime.internal.e.e(36234471, new com.quizlet.features.infra.folder.create.coursefolder.composable.h(z, bVar2, mVar, a, function12, function13, function1, function03, function04, bVar, z2, function14, function05), c0814p2), c0814p, 805306422, 188);
            nVar3 = nVar4;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.infra.folder.create.coursefolder.composable.c(nVar3, a, bVar, z, z2, z3, bVar2, mVar, function1, function12, function13, function0, function02, function03, function04, function14, function05, i, 1);
        }
    }

    public static final String b(com.quizlet.features.infra.folder.create.data.b createFolderState, InterfaceC0806l interfaceC0806l) {
        String strD;
        Intrinsics.checkNotNullParameter(createFolderState, "createFolderState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-786866313);
        if (createFolderState == com.quizlet.features.infra.folder.create.data.b.a) {
            strD = "";
        } else {
            if (createFolderState != com.quizlet.features.infra.folder.create.data.b.b) {
                throw new NoWhenBranchMatchedException();
            }
            strD = AbstractC3106b5.d(c0814p, R.string.edit_folder_title);
        }
        c0814p.p(false);
        return strD;
    }

    public static final String c(com.quizlet.features.infra.folder.create.data.b createFolderState, InterfaceC0806l interfaceC0806l) {
        int i;
        int i2;
        Intrinsics.checkNotNullParameter(createFolderState, "createFolderState");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-271291041);
        int iOrdinal = createFolderState.ordinal();
        if (iOrdinal == 0) {
            i = -860413098;
            i2 = R.string.create_folder_button;
        } else {
            if (iOrdinal != 1) {
                throw com.google.android.gms.measurement.internal.Z.j(-860415142, c0814p, false);
            }
            i = -860410188;
            i2 = R.string.edit_folder_button;
        }
        String strH = com.google.android.gms.measurement.internal.Z.h(c0814p, i, i2, c0814p, false);
        c0814p.p(false);
        return strH;
    }

    public static androidx.compose.ui.window.r d() {
        return new androidx.compose.ui.window.r(7);
    }

    public static final void e(String str) {
        throw new IllegalArgumentException(str);
    }
}
