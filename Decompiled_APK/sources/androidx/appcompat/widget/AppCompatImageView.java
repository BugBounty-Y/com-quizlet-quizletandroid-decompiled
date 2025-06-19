package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.util.AttributeSet;
import android.widget.ImageView;
import androidx.annotation.NonNull;

/* loaded from: classes.dex */
public class AppCompatImageView extends ImageView {
    public final C0105q a;
    public final C0122z b;
    public boolean c;

    public AppCompatImageView(@NonNull Context context) {
        this(context, null);
    }

    @Override // android.widget.ImageView, android.view.View
    public void drawableStateChanged() {
        super.drawableStateChanged();
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.a();
        }
        C0122z c0122z = this.b;
        if (c0122z != null) {
            c0122z.d();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0105q c0105q = this.a;
        if (c0105q != null) {
            return c0105q.b();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0105q c0105q = this.a;
        if (c0105q != null) {
            return c0105q.c();
        }
        return null;
    }

    public ColorStateList getSupportImageTintList() {
        o1 o1Var;
        C0122z c0122z = this.b;
        if (c0122z == null || (o1Var = (o1) c0122z.d) == null) {
            return null;
        }
        return (ColorStateList) o1Var.c;
    }

    public PorterDuff.Mode getSupportImageTintMode() {
        o1 o1Var;
        C0122z c0122z = this.b;
        if (c0122z == null || (o1Var = (o1) c0122z.d) == null) {
            return null;
        }
        return (PorterDuff.Mode) o1Var.d;
    }

    @Override // android.widget.ImageView, android.view.View
    public final boolean hasOverlappingRendering() {
        return !(((ImageView) this.b.c).getBackground() instanceof RippleDrawable) && super.hasOverlappingRendering();
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.e();
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.f(i);
        }
    }

    @Override // android.widget.ImageView
    public void setImageBitmap(Bitmap bitmap) {
        super.setImageBitmap(bitmap);
        C0122z c0122z = this.b;
        if (c0122z != null) {
            c0122z.d();
        }
    }

    @Override // android.widget.ImageView
    public void setImageDrawable(Drawable drawable) {
        C0122z c0122z = this.b;
        if (c0122z != null && drawable != null && !this.c) {
            c0122z.b = drawable.getLevel();
        }
        super.setImageDrawable(drawable);
        if (c0122z != null) {
            c0122z.d();
            if (this.c) {
                return;
            }
            ImageView imageView = (ImageView) c0122z.c;
            if (imageView.getDrawable() != null) {
                imageView.getDrawable().setLevel(c0122z.b);
            }
        }
    }

    @Override // android.widget.ImageView
    public void setImageLevel(int i) {
        super.setImageLevel(i);
        this.c = true;
    }

    @Override // android.widget.ImageView
    public void setImageResource(int i) {
        C0122z c0122z = this.b;
        if (c0122z != null) {
            c0122z.x(i);
        }
    }

    @Override // android.widget.ImageView
    public void setImageURI(Uri uri) {
        super.setImageURI(uri);
        C0122z c0122z = this.b;
        if (c0122z != null) {
            c0122z.d();
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.h(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.i(mode);
        }
    }

    public void setSupportImageTintList(ColorStateList colorStateList) {
        C0122z c0122z = this.b;
        if (c0122z != null) {
            if (((o1) c0122z.d) == null) {
                c0122z.d = new o1();
            }
            o1 o1Var = (o1) c0122z.d;
            o1Var.c = colorStateList;
            o1Var.b = true;
            c0122z.d();
        }
    }

    public void setSupportImageTintMode(PorterDuff.Mode mode) {
        C0122z c0122z = this.b;
        if (c0122z != null) {
            if (((o1) c0122z.d) == null) {
                c0122z.d = new o1();
            }
            o1 o1Var = (o1) c0122z.d;
            o1Var.d = mode;
            o1Var.a = true;
            c0122z.d();
        }
    }

    public AppCompatImageView(@NonNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AppCompatImageView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        n1.a(context);
        this.c = false;
        m1.a(getContext(), this);
        C0105q c0105q = new C0105q(this);
        this.a = c0105q;
        c0105q.d(attributeSet, i);
        C0122z c0122z = new C0122z(this);
        this.b = c0122z;
        c0122z.t(attributeSet, i);
    }
}
