package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.res.Configuration;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.o5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3223o5 implements androidx.compose.ui.text.android.selection.e {
    public static final /* synthetic */ int a = 0;

    public static final float a(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1392013472);
        float f = ((Configuration) c0814p.j(AndroidCompositionLocals_androidKt.a)).screenWidthDp / i;
        c0814p.p(false);
        return f;
    }

    @Override // androidx.compose.ui.text.android.selection.e
    public int b(int i) {
        int iD = d(i);
        if (iD == -1 || d(iD) == -1) {
            return -1;
        }
        return iD;
    }

    @Override // androidx.compose.ui.text.android.selection.e
    public int c(int i) {
        int iG = g(i);
        if (iG == -1 || g(iG) == -1) {
            return -1;
        }
        return iG;
    }

    public abstract int d(int i);

    @Override // androidx.compose.ui.text.android.selection.e
    public int e(int i) {
        return g(i);
    }

    @Override // androidx.compose.ui.text.android.selection.e
    public int f(int i) {
        return d(i);
    }

    public abstract int g(int i);
}
