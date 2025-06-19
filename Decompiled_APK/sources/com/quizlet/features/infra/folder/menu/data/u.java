package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u implements x {
    public final String a;
    public final com.quizlet.data.interactor.folderstudymaterial.g b;

    public u(String folderName, com.quizlet.data.interactor.folderstudymaterial.g undoAction) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        Intrinsics.checkNotNullParameter(undoAction, "undoAction");
        this.a = folderName;
        this.b = undoAction;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final com.quizlet.data.interactor.folderstudymaterial.g a() {
        return this.b;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final C0995g b(InterfaceC0806l interfaceC0806l) {
        C0995g c0995gD;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1444190136);
        com.quizlet.data.interactor.folderstudymaterial.g gVar = this.b;
        if ((gVar instanceof com.quizlet.data.interactor.folderstudymaterial.d) || (gVar instanceof com.quizlet.data.interactor.folderstudymaterial.f)) {
            c0814p.X(963135839);
            c0995gD = AbstractC3188k6.d(R.string.added_material_to_folder, R.string.removed_material_from_folder, c0814p, this.a, gVar instanceof com.quizlet.data.interactor.folderstudymaterial.f);
            c0814p.p(false);
        } else {
            if (!(gVar instanceof com.quizlet.data.interactor.folderstudymaterial.e)) {
                throw Z.j(963132845, c0814p, false);
            }
            c0814p.X(-207095929);
            C0984d c0984d = new C0984d();
            c0984d.f(AbstractC3106b5.d(c0814p, R.string.save_to_multiple_folders_changes_saved));
            c0995gD = c0984d.j();
            c0814p.p(false);
        }
        c0814p.p(false);
        return c0995gD;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof u)) {
            return false;
        }
        u uVar = (u) obj;
        return Intrinsics.b(this.a, uVar.a) && Intrinsics.b(this.b, uVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Success(folderName=" + this.a + ", undoAction=" + this.b + ")";
    }
}
