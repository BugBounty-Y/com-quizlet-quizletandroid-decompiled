package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class t implements x {
    public static final t a = new t();

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final com.quizlet.data.interactor.folderstudymaterial.g a() {
        return null;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final C0995g b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-482551857);
        C0995g c0995g = new C0995g(6, AbstractC3106b5.d(c0814p, R.string.client_error_net_exception), null);
        c0814p.p(false);
        return c0995g;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof t);
    }

    public final int hashCode() {
        return 1400766082;
    }

    public final String toString() {
        return "Failure";
    }
}
