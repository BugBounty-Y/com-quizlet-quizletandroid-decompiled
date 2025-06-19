package androidx.appcompat.widget;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.ListAdapter;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;
import android.widget.ThemedSpinnerAdapter;
import androidx.annotation.NonNull;
import androidx.appcompat.view.menu.ViewTreeObserverOnGlobalLayoutListenerC0067d;

/* loaded from: classes.dex */
public class AppCompatSpinner extends Spinner {
    public static final int[] i = {R.attr.spinnerMode};
    public final C0105q a;
    public final Context b;
    public final I c;
    public SpinnerAdapter d;
    public final boolean e;
    public final Q f;
    public int g;
    public final Rect h;

    public static class SavedState extends View.BaseSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new P();
        public boolean a;

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeByte(this.a ? (byte) 1 : (byte) 0);
        }
    }

    public AppCompatSpinner(@NonNull Context context) {
        this(context, null);
    }

    public final int a(SpinnerAdapter spinnerAdapter, Drawable drawable) {
        int i2 = 0;
        if (spinnerAdapter == null) {
            return 0;
        }
        int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 0);
        int iMakeMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(getMeasuredHeight(), 0);
        int iMax = Math.max(0, getSelectedItemPosition());
        int iMin = Math.min(spinnerAdapter.getCount(), iMax + 15);
        View view = null;
        int iMax2 = 0;
        for (int iMax3 = Math.max(0, iMax - (15 - (iMin - iMax))); iMax3 < iMin; iMax3++) {
            int itemViewType = spinnerAdapter.getItemViewType(iMax3);
            if (itemViewType != i2) {
                view = null;
                i2 = itemViewType;
            }
            view = spinnerAdapter.getView(iMax3, view, this);
            if (view.getLayoutParams() == null) {
                view.setLayoutParams(new ViewGroup.LayoutParams(-2, -2));
            }
            view.measure(iMakeMeasureSpec, iMakeMeasureSpec2);
            iMax2 = Math.max(iMax2, view.getMeasuredWidth());
        }
        if (drawable == null) {
            return iMax2;
        }
        Rect rect = this.h;
        drawable.getPadding(rect);
        return rect.left + rect.right + iMax2;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.a();
        }
    }

    @Override // android.widget.Spinner
    public int getDropDownHorizontalOffset() {
        Q q = this.f;
        return q != null ? q.b() : super.getDropDownHorizontalOffset();
    }

    @Override // android.widget.Spinner
    public int getDropDownVerticalOffset() {
        Q q = this.f;
        return q != null ? q.n() : super.getDropDownVerticalOffset();
    }

    @Override // android.widget.Spinner
    public int getDropDownWidth() {
        return this.f != null ? this.g : super.getDropDownWidth();
    }

    public final Q getInternalPopup() {
        return this.f;
    }

    @Override // android.widget.Spinner
    public Drawable getPopupBackground() {
        Q q = this.f;
        return q != null ? q.g() : super.getPopupBackground();
    }

    @Override // android.widget.Spinner
    public Context getPopupContext() {
        return this.b;
    }

    @Override // android.widget.Spinner
    public CharSequence getPrompt() {
        Q q = this.f;
        return q != null ? q.e() : super.getPrompt();
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

    @Override // android.widget.Spinner, android.widget.AdapterView, android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        Q q = this.f;
        if (q == null || !q.a()) {
            return;
        }
        q.dismiss();
    }

    @Override // android.widget.Spinner, android.widget.AbsSpinner, android.view.View
    public final void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        if (this.f == null || View.MeasureSpec.getMode(i2) != Integer.MIN_VALUE) {
            return;
        }
        setMeasuredDimension(Math.min(Math.max(getMeasuredWidth(), a(getAdapter(), getBackground())), View.MeasureSpec.getSize(i2)), getMeasuredHeight());
    }

    @Override // android.widget.Spinner, android.widget.AbsSpinner, android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        ViewTreeObserver viewTreeObserver;
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.getSuperState());
        if (!savedState.a || (viewTreeObserver = getViewTreeObserver()) == null) {
            return;
        }
        viewTreeObserver.addOnGlobalLayoutListener(new ViewTreeObserverOnGlobalLayoutListenerC0067d(this, 2));
    }

    @Override // android.widget.Spinner, android.widget.AbsSpinner, android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        Q q = this.f;
        savedState.a = q != null && q.a();
        return savedState;
    }

    @Override // android.widget.Spinner, android.view.View
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        I i2 = this.c;
        if (i2 == null || !i2.onTouch(this, motionEvent)) {
            return super.onTouchEvent(motionEvent);
        }
        return true;
    }

    @Override // android.widget.Spinner, android.view.View
    public final boolean performClick() {
        Q q = this.f;
        if (q == null) {
            return super.performClick();
        }
        if (q.a()) {
            return true;
        }
        this.f.m(getTextDirection(), getTextAlignment());
        return true;
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
    public void setBackgroundResource(int i2) {
        super.setBackgroundResource(i2);
        C0105q c0105q = this.a;
        if (c0105q != null) {
            c0105q.f(i2);
        }
    }

    @Override // android.widget.Spinner
    public void setDropDownHorizontalOffset(int i2) {
        Q q = this.f;
        if (q == null) {
            super.setDropDownHorizontalOffset(i2);
        } else {
            q.l(i2);
            q.d(i2);
        }
    }

    @Override // android.widget.Spinner
    public void setDropDownVerticalOffset(int i2) {
        Q q = this.f;
        if (q != null) {
            q.k(i2);
        } else {
            super.setDropDownVerticalOffset(i2);
        }
    }

    @Override // android.widget.Spinner
    public void setDropDownWidth(int i2) {
        if (this.f != null) {
            this.g = i2;
        } else {
            super.setDropDownWidth(i2);
        }
    }

    @Override // android.widget.Spinner
    public void setPopupBackgroundDrawable(Drawable drawable) {
        Q q = this.f;
        if (q != null) {
            q.j(drawable);
        } else {
            super.setPopupBackgroundDrawable(drawable);
        }
    }

    @Override // android.widget.Spinner
    public void setPopupBackgroundResource(int i2) {
        setPopupBackgroundDrawable(com.facebook.appevents.g.f(getPopupContext(), i2));
    }

    @Override // android.widget.Spinner
    public void setPrompt(CharSequence charSequence) {
        Q q = this.f;
        if (q != null) {
            q.h(charSequence);
        } else {
            super.setPrompt(charSequence);
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

    public AppCompatSpinner(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, com.quizlet.quizletandroid.R.attr.spinnerStyle);
    }

    @Override // android.widget.AdapterView
    public void setAdapter(SpinnerAdapter spinnerAdapter) {
        if (!this.e) {
            this.d = spinnerAdapter;
            return;
        }
        super.setAdapter(spinnerAdapter);
        Q q = this.f;
        if (q != null) {
            Context context = this.b;
            if (context == null) {
                context = getContext();
            }
            Resources.Theme theme = context.getTheme();
            L l = new L();
            l.a = spinnerAdapter;
            if (spinnerAdapter instanceof ListAdapter) {
                l.b = (ListAdapter) spinnerAdapter;
            }
            if (theme != null && (spinnerAdapter instanceof ThemedSpinnerAdapter)) {
                J.a((ThemedSpinnerAdapter) spinnerAdapter, theme);
            }
            q.p(l);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00c7  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00d4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public AppCompatSpinner(android.content.Context r12, android.util.AttributeSet r13, int r14) throws java.lang.Throwable {
        /*
            r11 = this;
            r11.<init>(r12, r13, r14)
            android.graphics.Rect r0 = new android.graphics.Rect
            r0.<init>()
            r11.h = r0
            android.content.Context r0 = r11.getContext()
            androidx.appcompat.widget.m1.a(r0, r11)
            int[] r0 = androidx.appcompat.a.w
            com.quizlet.data.repository.classfolder.e r1 = com.quizlet.data.repository.classfolder.e.m(r12, r13, r0, r14)
            androidx.appcompat.widget.q r2 = new androidx.appcompat.widget.q
            r2.<init>(r11)
            r11.a = r2
            r2 = 4
            java.lang.Object r3 = r1.c
            android.content.res.TypedArray r3 = (android.content.res.TypedArray) r3
            r4 = 0
            int r2 = r3.getResourceId(r2, r4)
            if (r2 == 0) goto L32
            androidx.appcompat.view.d r5 = new androidx.appcompat.view.d
            r5.<init>(r12, r2)
            r11.b = r5
            goto L34
        L32:
            r11.b = r12
        L34:
            r2 = -1
            r5 = 0
            int[] r6 = androidx.appcompat.widget.AppCompatSpinner.i     // Catch: java.lang.Throwable -> L51 java.lang.Exception -> L54
            android.content.res.TypedArray r6 = r12.obtainStyledAttributes(r13, r6, r14, r4)     // Catch: java.lang.Throwable -> L51 java.lang.Exception -> L54
            boolean r7 = r6.hasValue(r4)     // Catch: java.lang.Throwable -> L47 java.lang.Exception -> L4b
            if (r7 == 0) goto L4d
            int r2 = r6.getInt(r4, r4)     // Catch: java.lang.Throwable -> L47 java.lang.Exception -> L4b
            goto L4d
        L47:
            r12 = move-exception
            r5 = r6
            goto Ld2
        L4b:
            r7 = move-exception
            goto L56
        L4d:
            r6.recycle()
            goto L60
        L51:
            r12 = move-exception
            goto Ld2
        L54:
            r7 = move-exception
            r6 = r5
        L56:
            java.lang.String r8 = "AppCompatSpinner"
            java.lang.String r9 = "Could not read android:spinnerMode"
            android.util.Log.i(r8, r9, r7)     // Catch: java.lang.Throwable -> L47
            if (r6 == 0) goto L60
            goto L4d
        L60:
            r6 = 2
            r7 = 1
            if (r2 == 0) goto L9a
            if (r2 == r7) goto L67
            goto La7
        L67:
            androidx.appcompat.widget.O r2 = new androidx.appcompat.widget.O
            android.content.Context r8 = r11.b
            r2.<init>(r11, r8, r13, r14)
            android.content.Context r8 = r11.b
            com.quizlet.data.repository.classfolder.e r0 = com.quizlet.data.repository.classfolder.e.m(r8, r13, r0, r14)
            java.lang.Object r8 = r0.c
            android.content.res.TypedArray r8 = (android.content.res.TypedArray) r8
            r9 = 3
            r10 = -2
            int r8 = r8.getLayoutDimension(r9, r10)
            r11.g = r8
            android.graphics.drawable.Drawable r8 = r0.f(r7)
            r2.j(r8)
            java.lang.String r6 = r3.getString(r6)
            r2.C = r6
            r0.n()
            r11.f = r2
            androidx.appcompat.widget.I r0 = new androidx.appcompat.widget.I
            r0.<init>(r11, r11, r2)
            r11.c = r0
            goto La7
        L9a:
            androidx.appcompat.widget.K r0 = new androidx.appcompat.widget.K
            r0.<init>(r11)
            r11.f = r0
            java.lang.String r2 = r3.getString(r6)
            r0.c = r2
        La7:
            java.lang.CharSequence[] r0 = r3.getTextArray(r4)
            if (r0 == 0) goto Lbe
            android.widget.ArrayAdapter r2 = new android.widget.ArrayAdapter
            r3 = 17367048(0x1090008, float:2.5162948E-38)
            r2.<init>(r12, r3, r0)
            r12 = 2131625616(0x7f0e0690, float:1.8878445E38)
            r2.setDropDownViewResource(r12)
            r11.setAdapter(r2)
        Lbe:
            r1.n()
            r11.e = r7
            android.widget.SpinnerAdapter r12 = r11.d
            if (r12 == 0) goto Lcc
            r11.setAdapter(r12)
            r11.d = r5
        Lcc:
            androidx.appcompat.widget.q r12 = r11.a
            r12.d(r13, r14)
            return
        Ld2:
            if (r5 == 0) goto Ld7
            r5.recycle()
        Ld7:
            throw r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.AppCompatSpinner.<init>(android.content.Context, android.util.AttributeSet, int):void");
    }
}
