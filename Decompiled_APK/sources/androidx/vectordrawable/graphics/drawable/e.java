package androidx.vectordrawable.graphics.drawable;

import android.content.res.Resources;
import android.graphics.drawable.Drawable;

/* loaded from: classes.dex */
public final class e extends Drawable.ConstantState {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public boolean canApplyTheme() {
        switch (this.a) {
            case 0:
                return ((Drawable.ConstantState) this.b).canApplyTheme();
            default:
                return super.canApplyTheme();
        }
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public final int getChangingConfigurations() {
        switch (this.a) {
            case 0:
                return ((Drawable.ConstantState) this.b).getChangingConfigurations();
            case 1:
                return 0;
            default:
                return 0;
        }
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public final Drawable newDrawable() {
        switch (this.a) {
            case 0:
                f fVar = new f(null);
                Drawable drawableNewDrawable = ((Drawable.ConstantState) this.b).newDrawable();
                fVar.a = drawableNewDrawable;
                drawableNewDrawable.setCallback(fVar.f);
                return fVar;
            case 1:
                return new com.bumptech.glide.load.resource.gif.b(this);
            default:
                return (com.google.android.material.floatingactionbutton.b) this.b;
        }
    }

    public e(com.google.android.material.floatingactionbutton.b bVar) {
        this.a = 2;
        this.b = bVar;
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public Drawable newDrawable(Resources resources) {
        switch (this.a) {
            case 0:
                f fVar = new f(null);
                Drawable drawableNewDrawable = ((Drawable.ConstantState) this.b).newDrawable(resources);
                fVar.a = drawableNewDrawable;
                drawableNewDrawable.setCallback(fVar.f);
                return fVar;
            case 1:
                return new com.bumptech.glide.load.resource.gif.b(this);
            default:
                return super.newDrawable(resources);
        }
    }

    @Override // android.graphics.drawable.Drawable.ConstantState
    public Drawable newDrawable(Resources resources, Resources.Theme theme) {
        switch (this.a) {
            case 0:
                f fVar = new f(null);
                Drawable drawableNewDrawable = ((Drawable.ConstantState) this.b).newDrawable(resources, theme);
                fVar.a = drawableNewDrawable;
                drawableNewDrawable.setCallback(fVar.f);
                return fVar;
            default:
                return super.newDrawable(resources, theme);
        }
    }
}
