package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class v implements x {
    public static final v a = new v();

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final com.quizlet.data.interactor.folderstudymaterial.g a() {
        return null;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final C0995g b(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1237689364);
        C0984d c0984d = new C0984d();
        c0984d.f(AbstractC3106b5.d(c0814p, R.string.save_to_multiple_folders_changes_saved));
        C0995g c0995gJ = c0984d.j();
        c0814p.p(false);
        return c0995gJ;
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof v);
    }

    public final int hashCode() {
        return -1242502703;
    }

    public final String toString() {
        return "SuccessWithoutUndo";
    }
}
