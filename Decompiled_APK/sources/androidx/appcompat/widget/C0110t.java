package androidx.appcompat.widget;

import android.app.Activity;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.widget.CompoundButton;
import android.widget.TextView;
import com.google.android.gms.internal.ads.L9;
import com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2442od;
import com.google.android.gms.internal.ads.ViewTreeObserverOnGlobalLayoutListenerC2829xe;
import java.lang.ref.WeakReference;

/* renamed from: androidx.appcompat.widget.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0110t {
    public Object a;
    public Object b;
    public boolean c;
    public boolean d;
    public boolean e;
    public final View f;

    public C0110t(Activity activity, ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe, ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe2) {
        this.a = activity;
        this.f = viewTreeObserverOnGlobalLayoutListenerC2829xe;
        this.b = viewTreeObserverOnGlobalLayoutListenerC2829xe2;
    }

    public void a() {
        CompoundButton compoundButton = (CompoundButton) this.f;
        Drawable buttonDrawable = compoundButton.getButtonDrawable();
        if (buttonDrawable != null) {
            if (this.c || this.d) {
                Drawable drawableMutate = buttonDrawable.mutate();
                if (this.c) {
                    drawableMutate.setTintList((ColorStateList) this.a);
                }
                if (this.d) {
                    drawableMutate.setTintMode((PorterDuff.Mode) this.b);
                }
                if (drawableMutate.isStateful()) {
                    drawableMutate.setState(compoundButton.getDrawableState());
                }
                compoundButton.setButtonDrawable(drawableMutate);
            }
        }
    }

    public void b() {
        C0108s c0108s = (C0108s) this.f;
        Drawable checkMarkDrawable = c0108s.getCheckMarkDrawable();
        if (checkMarkDrawable != null) {
            if (this.c || this.d) {
                Drawable drawableMutate = checkMarkDrawable.mutate();
                if (this.c) {
                    drawableMutate.setTintList((ColorStateList) this.a);
                }
                if (this.d) {
                    drawableMutate.setTintMode((PorterDuff.Mode) this.b);
                }
                if (drawableMutate.isStateful()) {
                    drawableMutate.setState(c0108s.getDrawableState());
                }
                c0108s.setCheckMarkDrawable(drawableMutate);
            }
        }
    }

    public void c(AttributeSet attributeSet, int i) {
        int resourceId;
        int resourceId2;
        CompoundButton compoundButton = (CompoundButton) this.f;
        Context context = compoundButton.getContext();
        int[] iArr = androidx.appcompat.a.m;
        com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(context, attributeSet, iArr, i);
        TypedArray typedArray = (TypedArray) eVarM.c;
        androidx.core.view.V.n(compoundButton, compoundButton.getContext(), iArr, attributeSet, (TypedArray) eVarM.c, i);
        try {
            if (typedArray.hasValue(1) && (resourceId2 = typedArray.getResourceId(1, 0)) != 0) {
                try {
                    compoundButton.setButtonDrawable(com.facebook.appevents.g.f(compoundButton.getContext(), resourceId2));
                } catch (Resources.NotFoundException unused) {
                }
            } else if (typedArray.hasValue(0) && (resourceId = typedArray.getResourceId(0, 0)) != 0) {
                compoundButton.setButtonDrawable(com.facebook.appevents.g.f(compoundButton.getContext(), resourceId));
            }
            if (typedArray.hasValue(2)) {
                compoundButton.setButtonTintList(eVarM.e(2));
            }
            if (typedArray.hasValue(3)) {
                compoundButton.setButtonTintMode(AbstractC0102o0.c(typedArray.getInt(3, -1), null));
            }
            eVarM.n();
        } catch (Throwable th) {
            eVarM.n();
            throw th;
        }
    }

    public void d() {
        ViewTreeObserver viewTreeObserver;
        View decorView;
        if (this.c) {
            return;
        }
        Activity activity = (Activity) this.a;
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = (ViewTreeObserverOnGlobalLayoutListenerC2829xe) this.b;
        ViewTreeObserver viewTreeObserver2 = null;
        if (activity != null) {
            Window window = activity.getWindow();
            ViewTreeObserver viewTreeObserver3 = (window == null || (decorView = window.getDecorView()) == null) ? null : decorView.getViewTreeObserver();
            if (viewTreeObserver3 != null) {
                viewTreeObserver3.addOnGlobalLayoutListener(viewTreeObserverOnGlobalLayoutListenerC2829xe);
            }
        }
        L9 l9 = com.google.android.gms.ads.internal.j.C.B;
        ViewTreeObserverOnGlobalLayoutListenerC2442od viewTreeObserverOnGlobalLayoutListenerC2442od = new ViewTreeObserverOnGlobalLayoutListenerC2442od((ViewTreeObserverOnGlobalLayoutListenerC2829xe) this.f, viewTreeObserverOnGlobalLayoutListenerC2829xe);
        View view = (View) ((WeakReference) viewTreeObserverOnGlobalLayoutListenerC2442od.a).get();
        if (view != null && (viewTreeObserver = view.getViewTreeObserver()) != null && viewTreeObserver.isAlive()) {
            viewTreeObserver2 = viewTreeObserver;
        }
        if (viewTreeObserver2 != null) {
            viewTreeObserverOnGlobalLayoutListenerC2442od.k1(viewTreeObserver2);
        }
        this.c = true;
    }

    public /* synthetic */ C0110t(TextView textView) {
        this.a = null;
        this.b = null;
        this.c = false;
        this.d = false;
        this.f = textView;
    }
}
