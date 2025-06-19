package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.text.InputFilter;
import android.util.AttributeSet;
import android.widget.RadioButton;
import androidx.annotation.NonNull;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public class D extends RadioButton implements androidx.core.widget.q {
    public final C0110t a;
    public final C0105q b;
    public final Z c;
    public C0118x d;

    public D(Context context) {
        this(context, null, 0);
    }

    @NonNull
    private C0118x getEmojiTextViewHelper() {
        if (this.d == null) {
            this.d = new C0118x(this);
        }
        return this.d;
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.a();
        }
        Z z = this.c;
        if (z != null) {
            z.b();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0105q c0105q = this.b;
        if (c0105q != null) {
            return c0105q.b();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0105q c0105q = this.b;
        if (c0105q != null) {
            return c0105q.c();
        }
        return null;
    }

    @Override // androidx.core.widget.q
    public ColorStateList getSupportButtonTintList() {
        C0110t c0110t = this.a;
        if (c0110t != null) {
            return (ColorStateList) c0110t.a;
        }
        return null;
    }

    public PorterDuff.Mode getSupportButtonTintMode() {
        C0110t c0110t = this.a;
        if (c0110t != null) {
            return (PorterDuff.Mode) c0110t.b;
        }
        return null;
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.c.d();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.c.e();
    }

    @Override // android.widget.TextView
    public void setAllCaps(boolean z) {
        super.setAllCaps(z);
        getEmojiTextViewHelper().c(z);
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.e();
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.f(i);
        }
    }

    @Override // android.widget.CompoundButton
    public void setButtonDrawable(Drawable drawable) {
        super.setButtonDrawable(drawable);
        C0110t c0110t = this.a;
        if (c0110t != null) {
            if (c0110t.e) {
                c0110t.e = false;
            } else {
                c0110t.e = true;
                c0110t.a();
            }
        }
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
        Z z = this.c;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
        Z z = this.c;
        if (z != null) {
            z.b();
        }
    }

    public void setEmojiCompatEnabled(boolean z) {
        getEmojiTextViewHelper().d(z);
    }

    @Override // android.widget.TextView
    public void setFilters(@NonNull InputFilter[] inputFilterArr) {
        super.setFilters(getEmojiTextViewHelper().a(inputFilterArr));
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.h(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0105q c0105q = this.b;
        if (c0105q != null) {
            c0105q.i(mode);
        }
    }

    @Override // androidx.core.widget.q
    public void setSupportButtonTintList(ColorStateList colorStateList) {
        C0110t c0110t = this.a;
        if (c0110t != null) {
            c0110t.a = colorStateList;
            c0110t.c = true;
            c0110t.a();
        }
    }

    @Override // androidx.core.widget.q
    public void setSupportButtonTintMode(PorterDuff.Mode mode) {
        C0110t c0110t = this.a;
        if (c0110t != null) {
            c0110t.b = mode;
            c0110t.d = true;
            c0110t.a();
        }
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        Z z = this.c;
        z.k(colorStateList);
        z.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        Z z = this.c;
        z.l(mode);
        z.b();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, R.attr.radioButtonStyle);
        n1.a(context);
        m1.a(getContext(), this);
        C0110t c0110t = new C0110t(this);
        this.a = c0110t;
        c0110t.c(attributeSet, R.attr.radioButtonStyle);
        C0105q c0105q = new C0105q(this);
        this.b = c0105q;
        c0105q.d(attributeSet, R.attr.radioButtonStyle);
        Z z = new Z(this);
        this.c = z;
        z.f(attributeSet, R.attr.radioButtonStyle);
        getEmojiTextViewHelper().b(attributeSet, R.attr.radioButtonStyle);
    }

    @Override // android.widget.CompoundButton
    public void setButtonDrawable(int i) {
        setButtonDrawable(com.facebook.appevents.g.f(getContext(), i));
    }
}
