package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import android.text.Editable;
import android.text.TextWatcher;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements TextWatcher {
    public final /* synthetic */ int a;
    public final /* synthetic */ g b;

    public /* synthetic */ e(g gVar, int i) {
        this.a = i;
        this.b = gVar;
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable s) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(s, "s");
                g gVar = this.b;
                String strValueOf = String.valueOf(gVar.e().getText());
                if (!Intrinsics.b(gVar.f, strValueOf)) {
                    gVar.f = strValueOf;
                    String str = gVar.g;
                    com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = gVar.a;
                    fVar.getClass();
                    fVar.e.b(new androidx.core.util.c(strValueOf, str));
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(s, "s");
                g gVar2 = this.b;
                String strValueOf2 = String.valueOf(gVar2.c().getText());
                if (!Intrinsics.b(gVar2.g, strValueOf2)) {
                    gVar2.g = strValueOf2;
                    String str2 = gVar2.f;
                    com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = gVar2.a;
                    fVar2.getClass();
                    fVar2.e.b(new androidx.core.util.c(str2, strValueOf2));
                    break;
                }
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence s, int i, int i2, int i3) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
            default:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence s, int i, int i2, int i3) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
            default:
                Intrinsics.checkNotNullParameter(s, "s");
                break;
        }
    }
}
