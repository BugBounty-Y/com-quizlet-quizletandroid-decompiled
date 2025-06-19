package com.quizlet.quizletandroid.ui.login;

import android.text.Editable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.functions.h {
    public static final g b = new g(0);
    public static final g c = new g(1);
    public final /* synthetic */ int a;

    public /* synthetic */ g(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        String string;
        switch (this.a) {
            case 0:
                CharSequence it2 = (CharSequence) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return it2.toString();
            default:
                com.jakewharton.rxbinding4.widget.a it3 = (com.jakewharton.rxbinding4.widget.a) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                Editable editable = it3.b;
                return (editable == null || (string = editable.toString()) == null) ? "" : string;
        }
    }
}
