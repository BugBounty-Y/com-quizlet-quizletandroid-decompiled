package androidx.fragment.app;

import android.view.View;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1139j {
    public final H0 a;

    public AbstractC1139j(H0 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        this.a = operation;
    }

    public final boolean a() {
        J0 j0;
        H0 h0 = this.a;
        View view = h0.c.mView;
        J0 j02 = J0.b;
        if (view != null) {
            Intrinsics.checkNotNullParameter(view, "<this>");
            float alpha = view.getAlpha();
            j0 = J0.d;
            if (alpha != DefinitionKt.NO_Float_VALUE || view.getVisibility() != 0) {
                int visibility = view.getVisibility();
                if (visibility == 0) {
                    j0 = j02;
                } else if (visibility != 4) {
                    if (visibility != 8) {
                        throw new IllegalArgumentException(android.support.v4.media.session.a.f(visibility, "Unknown visibility "));
                    }
                    j0 = J0.c;
                }
            }
        } else {
            j0 = null;
        }
        J0 j03 = h0.a;
        if (j0 != j03) {
            return (j0 == j02 || j03 == j02) ? false : true;
        }
        return true;
    }
}
