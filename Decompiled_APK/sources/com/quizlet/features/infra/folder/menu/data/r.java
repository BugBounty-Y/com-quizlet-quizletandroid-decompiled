package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.features.infra.folder.menu.data.AddToFolderException;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements x {
    public final String a;
    public final AddToFolderException b;

    public r(String folderName, AddToFolderException exception) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        Intrinsics.checkNotNullParameter(exception, "exception");
        this.a = folderName;
        this.b = exception;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final com.quizlet.data.interactor.folderstudymaterial.g a() {
        return null;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final C0995g b(InterfaceC0806l interfaceC0806l) {
        C0995g c0995gD;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-974703536);
        AddToFolderException addToFolderException = this.b;
        boolean z = addToFolderException instanceof AddToFolderException.Adding;
        if (z || (addToFolderException instanceof AddToFolderException.Removing)) {
            c0814p.X(731033773);
            c0995gD = AbstractC3188k6.d(R.string.error_added_material_to_folder, R.string.error_removed_material_from_folder, c0814p, this.a, z);
            c0814p.p(false);
        } else {
            if (!(addToFolderException instanceof AddToFolderException.Multi)) {
                throw Z.j(731030769, c0814p, false);
            }
            c0814p.X(1187576285);
            C0984d c0984d = new C0984d();
            c0984d.f(AbstractC3106b5.d(c0814p, R.string.error_save_to_multiple_folders));
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
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return Intrinsics.b(this.a, rVar.a) && Intrinsics.b(this.b, rVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AddRemoveFailure(folderName=" + this.a + ", exception=" + this.b + ")";
    }
}
