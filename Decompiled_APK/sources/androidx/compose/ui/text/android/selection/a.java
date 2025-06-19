package androidx.compose.ui.text.android.selection;

import android.text.SegmentFinder;

/* loaded from: classes.dex */
public final class a extends SegmentFinder {
    public final /* synthetic */ e a;

    public a(e eVar) {
        this.a = eVar;
    }

    public final int nextEndBoundary(int i) {
        return this.a.f(i);
    }

    public final int nextStartBoundary(int i) {
        return this.a.b(i);
    }

    public final int previousEndBoundary(int i) {
        return this.a.c(i);
    }

    public final int previousStartBoundary(int i) {
        return this.a.e(i);
    }
}
