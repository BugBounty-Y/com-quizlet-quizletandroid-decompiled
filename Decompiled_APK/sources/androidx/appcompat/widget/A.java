package androidx.appcompat.widget;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.text.method.KeyListener;
import android.text.method.NumberKeyListener;
import android.util.AttributeSet;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.MultiAutoCompleteTextView;
import androidx.annotation.NonNull;

/* loaded from: classes.dex */
public class A extends MultiAutoCompleteTextView {
    public static final int[] d = {R.attr.popupBackground};
    public final C0105q a;
    public final Z b;
    public final C c;

    public A(@NonNull Context context) {
        this(context, null);
    }

    @Override // android.widget.TextView, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.a();
        }
        Z z = this.b;
        if (z != null) {
            z.b();
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

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.b.d();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.b.e();
    }

    @Override // android.widget.TextView, android.view.View
    public final InputConnection onCreateInputConnection(EditorInfo editorInfo) {
        InputConnection inputConnectionOnCreateInputConnection = super.onCreateInputConnection(editorInfo);
        com.facebook.appevents.i.c(inputConnectionOnCreateInputConnection, editorInfo, this);
        return this.c.c(inputConnectionOnCreateInputConnection, editorInfo);
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

    @Override // android.widget.TextView
    public final void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
        Z z = this.b;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
        Z z = this.b;
        if (z != null) {
            z.b();
        }
    }

    @Override // android.widget.AutoCompleteTextView
    public void setDropDownBackgroundResource(int i) {
        setDropDownBackgroundDrawable(com.facebook.appevents.g.f(getContext(), i));
    }

    public void setEmojiCompatEnabled(boolean z) {
        this.c.d(z);
    }

    @Override // android.widget.TextView
    public void setKeyListener(KeyListener keyListener) {
        super.setKeyListener(this.c.a(keyListener));
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

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        Z z = this.b;
        z.k(colorStateList);
        z.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        Z z = this.b;
        z.l(mode);
        z.b();
    }

    @Override // android.widget.TextView
    public final void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        Z z = this.b;
        if (z != null) {
            z.g(context, i);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, com.quizlet.quizletandroid.R.attr.autoCompleteTextViewStyle);
        n1.a(context);
        m1.a(getContext(), this);
        com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(getContext(), attributeSet, d, com.quizlet.quizletandroid.R.attr.autoCompleteTextViewStyle);
        if (((TypedArray) eVarM.c).hasValue(0)) {
            setDropDownBackgroundDrawable(eVarM.f(0));
        }
        eVarM.n();
        C0105q c0105q = new C0105q(this);
        this.a = c0105q;
        c0105q.d(attributeSet, com.quizlet.quizletandroid.R.attr.autoCompleteTextViewStyle);
        Z z = new Z(this);
        this.b = z;
        z.f(attributeSet, com.quizlet.quizletandroid.R.attr.autoCompleteTextViewStyle);
        z.b();
        C c = new C(this);
        this.c = c;
        c.b(attributeSet, com.quizlet.quizletandroid.R.attr.autoCompleteTextViewStyle);
        KeyListener keyListener = getKeyListener();
        if (keyListener instanceof NumberKeyListener) {
            return;
        }
        boolean zIsFocusable = super.isFocusable();
        boolean zIsClickable = super.isClickable();
        boolean zIsLongClickable = super.isLongClickable();
        int inputType = super.getInputType();
        KeyListener keyListenerA = c.a(keyListener);
        if (keyListenerA == keyListener) {
            return;
        }
        super.setKeyListener(keyListenerA);
        super.setRawInputType(inputType);
        super.setFocusable(zIsFocusable);
        super.setClickable(zIsClickable);
        super.setLongClickable(zIsLongClickable);
    }
}
