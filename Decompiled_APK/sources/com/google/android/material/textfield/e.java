package com.google.android.material.textfield;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3490l4;
import com.google.android.material.internal.CheckableImageButton;

/* loaded from: classes2.dex */
public final class e extends m {
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(l lVar, int i) {
        super(lVar);
        this.e = i;
    }

    @Override // com.google.android.material.textfield.m
    public void r() {
        switch (this.e) {
            case 0:
                l lVar = this.b;
                lVar.o = null;
                CheckableImageButton checkableImageButton = lVar.g;
                checkableImageButton.setOnLongClickListener(null);
                AbstractC3490l4.d(checkableImageButton, null);
                break;
        }
    }
}
