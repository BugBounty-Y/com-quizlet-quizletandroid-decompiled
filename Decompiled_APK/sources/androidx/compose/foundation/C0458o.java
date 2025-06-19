package androidx.compose.foundation;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.EdgeEffect;
import com.skydoves.balloon.internals.DefinitionKt;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.foundation.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0458o {
    public static final C0458o a = new C0458o();

    @NotNull
    public final EdgeEffect a(@NotNull Context context, AttributeSet attributeSet) {
        try {
            return new EdgeEffect(context, attributeSet);
        } catch (Throwable unused) {
            return new EdgeEffect(context);
        }
    }

    public final float b(@NotNull EdgeEffect edgeEffect) {
        try {
            return edgeEffect.getDistance();
        } catch (Throwable unused) {
            return DefinitionKt.NO_Float_VALUE;
        }
    }

    public final float c(@NotNull EdgeEffect edgeEffect, float f, float f2) {
        try {
            return edgeEffect.onPullDistance(f, f2);
        } catch (Throwable unused) {
            edgeEffect.onPull(f, f2);
            return DefinitionKt.NO_Float_VALUE;
        }
    }
}
