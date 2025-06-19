package com.quizlet.quizletandroid.ui.common.ads;

import android.view.ViewGroup;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.W;

/* renamed from: com.quizlet.quizletandroid.ui.common.ads.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4639f {
    public final ViewGroup a;
    public final W b;
    public final InterfaceC4638e c;

    public C4639f(ViewGroup view, W events, InterfaceC4638e loader) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(events, "events");
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.a = view;
        this.b = events;
        this.c = loader;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4639f)) {
            return false;
        }
        C4639f c4639f = (C4639f) obj;
        return Intrinsics.b(this.a, c4639f.a) && Intrinsics.b(this.b, c4639f.b) && this.c.equals(c4639f.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "BannerAdModel(view=" + this.a + ", events=" + this.b + ", loader=" + this.c + ")";
    }
}
