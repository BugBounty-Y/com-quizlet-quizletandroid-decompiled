package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Build;
import android.view.View;
import android.view.Window;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import kotlin.jvm.functions.Function0;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.u6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3275u6 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.ui.n nVar, boolean z, boolean z2, Function0 function0, Function0 function02, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(701854398);
        int i2 = i | 6;
        if ((i & 48) == 0) {
            i2 |= c0814p2.g(z) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.g(z2) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.h(function0) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(function02) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            nVar2 = nVar;
            c0814p = c0814p2;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            c0814p = c0814p2;
            AbstractC3691o6.b(com.quizlet.features.infra.folder.tag.composable.e.a, nVar3, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.g(), 0L, 0L, null, androidx.compose.runtime.internal.e.e(1999559540, new com.quizlet.explanations.questiondetail.ui.composables.m(9, function0), c0814p2), androidx.compose.runtime.internal.e.e(-1358241891, new com.quizlet.features.infra.folder.create.coursefolder.composable.l(z2, function02, z, 1), c0814p2), c0814p, ((i2 << 3) & ContentType.LONG_FORM_ON_DEMAND) | 14155782, 56);
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.tabs.c(nVar2, z, z2, function0, function02, i);
        }
    }

    public static void b(Window window, boolean z) {
        int i = Build.VERSION.SDK_INT;
        if (i >= 35) {
            androidx.camera.core.impl.utils.d.g(window, z);
        } else {
            if (i >= 30) {
                androidx.camera.core.impl.utils.d.f(window, z);
                return;
            }
            View decorView = window.getDecorView();
            int systemUiVisibility = decorView.getSystemUiVisibility();
            decorView.setSystemUiVisibility(z ? systemUiVisibility & (-1793) : systemUiVisibility | 1792);
        }
    }
}
