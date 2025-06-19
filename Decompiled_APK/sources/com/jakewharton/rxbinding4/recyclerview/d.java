package com.jakewharton.rxbinding4.recyclerview;

import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.F;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends F {
    public final RecyclerView a;
    public final View b;

    public d(RecyclerView view, View child) {
        Intrinsics.f(view, "view");
        Intrinsics.f(child, "child");
        this.a = view;
        this.b = child;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b);
    }

    public final int hashCode() {
        RecyclerView recyclerView = this.a;
        int iHashCode = (recyclerView != null ? recyclerView.hashCode() : 0) * 31;
        View view = this.b;
        return iHashCode + (view != null ? view.hashCode() : 0);
    }

    public final String toString() {
        return "RecyclerViewChildDetachEvent(view=" + this.a + ", child=" + this.b + ")";
    }
}
