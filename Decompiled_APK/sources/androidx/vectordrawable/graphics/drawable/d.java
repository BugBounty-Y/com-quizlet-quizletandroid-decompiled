package androidx.vectordrawable.graphics.drawable;

import android.animation.AnimatorSet;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import androidx.collection.C0208f;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class d extends Drawable.ConstantState {
    public p a;
    public AnimatorSet b;
    public ArrayList c;
    public C0208f d;

    @Override // android.graphics.drawable.Drawable.ConstantState
    public final int getChangingConfigurations() {
        return 0;
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public final Drawable newDrawable() {
        throw new IllegalStateException("No constant state support for SDK < 24.");
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public final Drawable newDrawable(Resources resources) {
        throw new IllegalStateException("No constant state support for SDK < 24.");
    }
}
