package androidx.compose.ui.text.android.selection;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5;
import java.text.BreakIterator;

/* loaded from: classes.dex */
public final class d extends AbstractC3223o5 {
    public final BreakIterator b;

    public d(CharSequence charSequence) {
        BreakIterator characterInstance = BreakIterator.getCharacterInstance();
        characterInstance.setText(charSequence.toString());
        this.b = characterInstance;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5
    public final int d(int i) {
        return this.b.following(i);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5
    public final int g(int i) {
        return this.b.preceding(i);
    }
}
