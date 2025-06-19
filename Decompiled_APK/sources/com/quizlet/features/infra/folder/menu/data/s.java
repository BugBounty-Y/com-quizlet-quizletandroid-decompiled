package com.quizlet.features.infra.folder.menu.data;

import androidx.compose.animation.d0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.U;
import androidx.compose.ui.text.C0984d;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.D;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class s implements x {
    public final String a;
    public final int b;
    public final h c;

    public s(String folderName, int i, h type) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = folderName;
        this.b = i;
        this.c = type;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final com.quizlet.data.interactor.folderstudymaterial.g a() {
        return null;
    }

    @Override // com.quizlet.features.infra.folder.menu.data.x
    public final C0995g b(InterfaceC0806l interfaceC0806l) {
        int i;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(355461649);
        int iOrdinal = this.c.ordinal();
        if (iOrdinal == 0) {
            i = R.plurals.added_materials_to_folder;
        } else if (iOrdinal == 1) {
            i = R.plurals.removed_materials_from_folder;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            i = R.plurals.updated_materials_to_folder;
        }
        String folderName = this.a;
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        c0814p.X(-1120337178);
        C0984d c0984d = new C0984d();
        int i2 = this.b;
        String strB = AbstractC3106b5.b(i, i2, new Object[]{Integer.valueOf(i2), folderName}, c0814p);
        c0984d.f(strB);
        c0984d.c(new D(0L, 0L, androidx.compose.ui.text.font.u.i, (androidx.compose.ui.text.font.q) null, (androidx.compose.ui.text.font.r) null, (androidx.compose.ui.text.font.j) null, (String) null, 0L, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, 0L, (androidx.compose.ui.text.style.j) null, (U) null, 65531), StringsKt.M(strB, folderName, 0, false, 6), folderName.length() + StringsKt.M(strB, folderName, 0, false, 6));
        C0995g c0995gJ = c0984d.j();
        c0814p.p(false);
        c0814p.p(false);
        return c0995gJ;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        return Intrinsics.b(this.a, sVar.a) && this.b == sVar.b && this.c == sVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        return "AddRemoveMultipleMaterialsSuccess(folderName=" + this.a + ", itemCount=" + this.b + ", type=" + this.c + ")";
    }
}
