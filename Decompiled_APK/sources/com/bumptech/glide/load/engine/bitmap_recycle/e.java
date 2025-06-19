package com.bumptech.glide.load.engine.bitmap_recycle;

import androidx.compose.animation.core.J0;

/* loaded from: classes.dex */
public final class e extends J0 {
    public final /* synthetic */ int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(int i) {
        super(4);
        this.c = i;
    }

    public final g T() {
        switch (this.c) {
            case 0:
                return new d(this);
            default:
                return new i(this);
        }
    }
}
