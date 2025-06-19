package org.wordpress.aztec.watchers;

import android.text.Editable;
import android.text.TextWatcher;
import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements TextWatcher {
    public boolean a;

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable text) {
        Intrinsics.checkNotNullParameter(text, "text");
        Y2.a(text, this.a);
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence s, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(s, "s");
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence s, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(s, "s");
        this.a = i2 > 0;
    }
}
