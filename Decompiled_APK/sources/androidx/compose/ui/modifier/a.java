package androidx.compose.ui.modifier;

import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_barcode.X4;

/* loaded from: classes.dex */
public final class a extends X4 {
    public f b;

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X4
    public final boolean a(h hVar) {
        return hVar == this.b.getKey();
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.X4
    public final Object b(h hVar) {
        if (hVar == this.b.getKey()) {
            return this.b.getValue();
        }
        W4.f("Check failed.");
        throw null;
    }
}
