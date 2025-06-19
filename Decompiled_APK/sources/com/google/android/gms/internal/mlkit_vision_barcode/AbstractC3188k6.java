package com.google.android.gms.internal.mlkit_vision_barcode;

import android.view.View;
import android.widget.FrameLayout;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.k6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3188k6 {
    public static final void a(View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        com.quizlet.quizletandroid.ui.setcreation.imageupload.a aVar = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(21);
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        androidx.core.view.L.m(view, aVar);
    }

    public static int b(int i, int i2, int i3) {
        return i < i2 ? i2 : i > i3 ? i3 : i;
    }

    public static final void c(FrameLayout frameLayout) {
        Intrinsics.checkNotNullParameter(frameLayout, "<this>");
        if (frameLayout.getChildCount() > 0) {
            frameLayout.removeAllViews();
        }
    }

    public static final C0995g d(int i, int i2, InterfaceC0806l interfaceC0806l, String folderName, boolean z) {
        String strC;
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-99395130);
        C0984d c0984d = new C0984d();
        if (z) {
            c0814p.X(582865821);
            strC = AbstractC3106b5.c(i, new Object[]{folderName}, c0814p);
            c0814p.p(false);
        } else {
            c0814p.X(582928410);
            strC = AbstractC3106b5.c(i2, new Object[]{folderName}, c0814p);
            c0814p.p(false);
        }
        c0984d.f(strC);
        c0984d.c(new androidx.compose.ui.text.D(0L, 0L, androidx.compose.ui.text.font.u.i, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (androidx.compose.ui.graphics.U) null, 65531), StringsKt.M(strC, folderName, 0, false, 6), folderName.length() + StringsKt.M(strC, folderName, 0, false, 6));
        C0995g c0995gJ = c0984d.j();
        c0814p.p(false);
        return c0995gJ;
    }
}
