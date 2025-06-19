package com.mayakapps.kache.collection;

import kotlin.jvm.internal.Intrinsics;
import kotlin.time.TimeMark;

/* loaded from: classes2.dex */
public final class e extends androidx.compose.ui.text.android.selection.f {
    public final kotlin.time.h f;
    public TimeMark[] g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(kotlin.time.h timeSource) {
        super(8, (byte) 0);
        Intrinsics.checkNotNullParameter(timeSource, "timeSource");
        this.f = timeSource;
        this.g = new TimeMark[0];
    }

    @Override // androidx.compose.ui.text.android.selection.f
    public final void a(int i) {
        super.a(i);
        this.g[i] = this.f.a();
    }

    @Override // androidx.compose.ui.text.android.selection.f
    public final Object[] c() {
        return this.g;
    }

    @Override // androidx.compose.ui.text.android.selection.f
    public final void e(int i) {
        super.e(i);
        TimeMark[] timeMarkArr = new TimeMark[i];
        for (int i2 = 0; i2 < i; i2++) {
            timeMarkArr[i2] = null;
        }
        this.g = timeMarkArr;
    }

    @Override // androidx.compose.ui.text.android.selection.f
    public final void k(int i) {
        super.k(i);
        this.g[i] = this.f.a();
    }

    @Override // androidx.compose.ui.text.android.selection.f
    public final void l(int i) {
        super.l(i);
        this.g[i] = null;
    }
}
