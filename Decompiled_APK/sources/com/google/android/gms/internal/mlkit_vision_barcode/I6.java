package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.res.Resources;
import android.view.View;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public abstract class I6 {
    public static final int[] a(String str) {
        int[] iArr = new int[256];
        for (int i = 0; i < 256; i++) {
            iArr[i] = -1;
        }
        int length = str.length();
        for (int i2 = 0; i2 < length; i2++) {
            iArr[str.charAt(i2)] = i2;
        }
        return iArr;
    }

    public static com.google.android.material.snackbar.h d(View view, String str) {
        int iA = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.colorPrimaryDark);
        com.quizlet.features.infra.snackbar.b bVar = new com.quizlet.features.infra.snackbar.b(view);
        bVar.b = str;
        bVar.g = R.dimen.snackbar_text_size;
        bVar.d = iA;
        bVar.e = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColor);
        bVar.h = R.drawable.gray_ripple_unbounded;
        return bVar.a();
    }

    public static com.google.android.material.snackbar.h e(View view, String str) {
        com.quizlet.features.infra.snackbar.b bVar = new com.quizlet.features.infra.snackbar.b(view);
        bVar.b = str;
        bVar.g = R.dimen.snackbar_text_size;
        bVar.d = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.colorControlError);
        bVar.e = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColorInverse);
        return bVar.a();
    }

    public static com.google.android.material.snackbar.h f(View view, String str) throws Resources.NotFoundException {
        com.quizlet.features.infra.snackbar.b bVar = new com.quizlet.features.infra.snackbar.b(view);
        bVar.b = str;
        bVar.g = R.dimen.snackbar_text_size;
        bVar.d = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.colorBackgroundInverse);
        bVar.e = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColorInverse);
        com.google.android.material.snackbar.h hVarA = bVar.a();
        hVarA.k = -2;
        return hVarA;
    }

    public abstract int b(int i, View view);

    public abstract int c(int i, View view);

    public int g(View view) {
        return 0;
    }

    public int h() {
        return 0;
    }

    public void i(int i, View view) {
    }

    public abstract void j(int i);

    public abstract void k(View view, int i, int i2);

    public abstract void l(View view, float f, float f2);

    public abstract boolean m(int i, View view);
}
