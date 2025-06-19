package androidx.compose.foundation.text;

import androidx.compose.ui.text.C0995g;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;
import java.util.List;

/* loaded from: classes.dex */
public final class t0 {
    public final C0995g a;
    public final androidx.compose.ui.text.L b;
    public final boolean e;
    public final androidx.compose.ui.unit.b g;
    public final androidx.compose.ui.text.font.i h;
    public final List i;
    public com.quizlet.remote.model.notes.e j;
    public androidx.compose.ui.unit.k k;
    public final int c = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public final int d = 1;
    public final int f = 1;

    public t0(C0995g c0995g, androidx.compose.ui.text.L l, boolean z, androidx.compose.ui.unit.b bVar, androidx.compose.ui.text.font.i iVar, List list) {
        this.a = c0995g;
        this.b = l;
        this.e = z;
        this.g = bVar;
        this.h = iVar;
        this.i = list;
    }

    public final void a(androidx.compose.ui.unit.k kVar) {
        com.quizlet.remote.model.notes.e eVar = this.j;
        if (eVar == null || kVar != this.k || eVar.a()) {
            this.k = kVar;
            eVar = new com.quizlet.remote.model.notes.e(this.a, AbstractC3214n5.c(this.b, kVar), this.i, this.g, this.h);
        }
        this.j = eVar;
    }
}
