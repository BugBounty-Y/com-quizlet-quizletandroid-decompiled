package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Handler;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListAdapter;
import android.widget.PopupWindow;
import androidx.annotation.NonNull;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.Method;

/* loaded from: classes.dex */
public class G0 implements androidx.appcompat.view.menu.D {
    public static final Method A;
    public static final Method B;
    public final Context a;
    public ListAdapter b;
    public C0113u0 c;
    public final int d;
    public int e;
    public int f;
    public int g;
    public final int h;
    public boolean i;
    public boolean j;
    public boolean k;
    public int l;
    public final int m;
    public D0 n;
    public View o;
    public AdapterView.OnItemClickListener p;
    public AdapterView.OnItemSelectedListener q;
    public final C0 r;
    public final F0 s;
    public final E0 t;
    public final C0 u;
    public final Handler v;
    public final Rect w;
    public Rect x;
    public boolean y;
    public final B z;

    static {
        if (Build.VERSION.SDK_INT <= 28) {
            try {
                A = PopupWindow.class.getDeclaredMethod("setClipToScreenEnabled", Boolean.TYPE);
            } catch (NoSuchMethodException unused) {
                Log.i("ListPopupWindow", "Could not find method setClipToScreenEnabled() on PopupWindow. Oh well.");
            }
            try {
                B = PopupWindow.class.getDeclaredMethod("setEpicenterBounds", Rect.class);
            } catch (NoSuchMethodException unused2) {
                Log.i("ListPopupWindow", "Could not find method setEpicenterBounds(Rect) on PopupWindow. Oh well.");
            }
        }
    }

    public G0(@NonNull Context context) {
        this(context, null, R.attr.listPopupWindowStyle);
    }

    @Override // androidx.appcompat.view.menu.D
    public final boolean a() {
        return this.z.isShowing();
    }

    public final int b() {
        return this.f;
    }

    public final void d(int i) {
        this.f = i;
    }

    @Override // androidx.appcompat.view.menu.D
    public final void dismiss() {
        B b = this.z;
        b.dismiss();
        b.setContentView(null);
        this.c = null;
        this.v.removeCallbacks(this.r);
    }

    @Override // androidx.appcompat.view.menu.D
    public final void f() {
        int i;
        int paddingBottom;
        C0113u0 c0113u0;
        C0113u0 c0113u02 = this.c;
        B b = this.z;
        Context context = this.a;
        if (c0113u02 == null) {
            C0113u0 c0113u0Q = q(context, !this.y);
            this.c = c0113u0Q;
            c0113u0Q.setAdapter(this.b);
            this.c.setOnItemClickListener(this.p);
            this.c.setFocusable(true);
            this.c.setFocusableInTouchMode(true);
            this.c.setOnItemSelectedListener(new C0123z0(this, 0));
            this.c.setOnScrollListener(this.t);
            AdapterView.OnItemSelectedListener onItemSelectedListener = this.q;
            if (onItemSelectedListener != null) {
                this.c.setOnItemSelectedListener(onItemSelectedListener);
            }
            b.setContentView(this.c);
        }
        Drawable background = b.getBackground();
        Rect rect = this.w;
        if (background != null) {
            background.getPadding(rect);
            int i2 = rect.top;
            i = rect.bottom + i2;
            if (!this.i) {
                this.g = -i2;
            }
        } else {
            rect.setEmpty();
            i = 0;
        }
        int iA = A0.a(b, this.o, this.g, b.getInputMethodMode() == 2);
        int i3 = this.d;
        if (i3 == -1) {
            paddingBottom = iA + i;
        } else {
            int i4 = this.e;
            int iA2 = this.c.a(i4 != -2 ? i4 != -1 ? View.MeasureSpec.makeMeasureSpec(i4, 1073741824) : View.MeasureSpec.makeMeasureSpec(context.getResources().getDisplayMetrics().widthPixels - (rect.left + rect.right), 1073741824) : View.MeasureSpec.makeMeasureSpec(context.getResources().getDisplayMetrics().widthPixels - (rect.left + rect.right), Integer.MIN_VALUE), iA);
            paddingBottom = iA2 + (iA2 > 0 ? this.c.getPaddingBottom() + this.c.getPaddingTop() + i : 0);
        }
        boolean z = this.z.getInputMethodMode() == 2;
        b.setWindowLayoutType(this.h);
        if (b.isShowing()) {
            if (this.o.isAttachedToWindow()) {
                int width = this.e;
                if (width == -1) {
                    width = -1;
                } else if (width == -2) {
                    width = this.o.getWidth();
                }
                if (i3 == -1) {
                    i3 = z ? paddingBottom : -1;
                    if (z) {
                        b.setWidth(this.e == -1 ? -1 : 0);
                        b.setHeight(0);
                    } else {
                        b.setWidth(this.e == -1 ? -1 : 0);
                        b.setHeight(-1);
                    }
                } else if (i3 == -2) {
                    i3 = paddingBottom;
                }
                b.setOutsideTouchable(true);
                View view = this.o;
                int i5 = this.f;
                int i6 = this.g;
                if (width < 0) {
                    width = -1;
                }
                b.update(view, i5, i6, width, i3 < 0 ? -1 : i3);
                return;
            }
            return;
        }
        int width2 = this.e;
        if (width2 == -1) {
            width2 = -1;
        } else if (width2 == -2) {
            width2 = this.o.getWidth();
        }
        if (i3 == -1) {
            i3 = -1;
        } else if (i3 == -2) {
            i3 = paddingBottom;
        }
        b.setWidth(width2);
        b.setHeight(i3);
        if (Build.VERSION.SDK_INT <= 28) {
            Method method = A;
            if (method != null) {
                try {
                    method.invoke(b, Boolean.TRUE);
                } catch (Exception unused) {
                    Log.i("ListPopupWindow", "Could not call setClipToScreenEnabled() on PopupWindow. Oh well.");
                }
            }
        } else {
            B0.b(b, true);
        }
        b.setOutsideTouchable(true);
        b.setTouchInterceptor(this.s);
        if (this.k) {
            b.setOverlapAnchor(this.j);
        }
        if (Build.VERSION.SDK_INT <= 28) {
            Method method2 = B;
            if (method2 != null) {
                try {
                    method2.invoke(b, this.x);
                } catch (Exception e) {
                    Log.e("ListPopupWindow", "Could not invoke setEpicenterBounds on PopupWindow", e);
                }
            }
        } else {
            B0.a(b, this.x);
        }
        b.showAsDropDown(this.o, this.f, this.g, this.l);
        this.c.setSelection(-1);
        if ((!this.y || this.c.isInTouchMode()) && (c0113u0 = this.c) != null) {
            c0113u0.setListSelectionHidden(true);
            c0113u0.requestLayout();
        }
        if (this.y) {
            return;
        }
        this.v.post(this.u);
    }

    public final Drawable g() {
        return this.z.getBackground();
    }

    @Override // androidx.appcompat.view.menu.D
    public final C0113u0 i() {
        return this.c;
    }

    public final void j(Drawable drawable) {
        this.z.setBackgroundDrawable(drawable);
    }

    public final void k(int i) {
        this.g = i;
        this.i = true;
    }

    public final int n() {
        if (this.i) {
            return this.g;
        }
        return 0;
    }

    public void p(ListAdapter listAdapter) {
        D0 d0 = this.n;
        if (d0 == null) {
            this.n = new D0(this, 0);
        } else {
            ListAdapter listAdapter2 = this.b;
            if (listAdapter2 != null) {
                listAdapter2.unregisterDataSetObserver(d0);
            }
        }
        this.b = listAdapter;
        if (listAdapter != null) {
            listAdapter.registerDataSetObserver(this.n);
        }
        C0113u0 c0113u0 = this.c;
        if (c0113u0 != null) {
            c0113u0.setAdapter(this.b);
        }
    }

    public C0113u0 q(Context context, boolean z) {
        return new C0113u0(context, z);
    }

    public final void r(int i) {
        Drawable background = this.z.getBackground();
        if (background == null) {
            this.e = i;
            return;
        }
        Rect rect = this.w;
        background.getPadding(rect);
        this.e = rect.left + rect.right + i;
    }

    public G0(Context context, AttributeSet attributeSet, int i) {
        int resourceId;
        this.d = -2;
        this.e = -2;
        this.h = 1002;
        this.l = 0;
        this.m = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.r = new C0(this, 1);
        this.s = new F0(this, 0);
        this.t = new E0(this);
        this.u = new C0(this, 0);
        this.w = new Rect();
        this.a = context;
        this.v = new Handler(context.getMainLooper());
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, androidx.appcompat.a.p, i, 0);
        this.f = typedArrayObtainStyledAttributes.getDimensionPixelOffset(0, 0);
        int dimensionPixelOffset = typedArrayObtainStyledAttributes.getDimensionPixelOffset(1, 0);
        this.g = dimensionPixelOffset;
        if (dimensionPixelOffset != 0) {
            this.i = true;
        }
        typedArrayObtainStyledAttributes.recycle();
        B b = new B(context, attributeSet, i, 0);
        TypedArray typedArrayObtainStyledAttributes2 = context.obtainStyledAttributes(attributeSet, androidx.appcompat.a.t, i, 0);
        if (typedArrayObtainStyledAttributes2.hasValue(2)) {
            b.setOverlapAnchor(typedArrayObtainStyledAttributes2.getBoolean(2, false));
        }
        b.setBackgroundDrawable((!typedArrayObtainStyledAttributes2.hasValue(0) || (resourceId = typedArrayObtainStyledAttributes2.getResourceId(0, 0)) == 0) ? typedArrayObtainStyledAttributes2.getDrawable(0) : com.facebook.appevents.g.f(context, resourceId));
        typedArrayObtainStyledAttributes2.recycle();
        this.z = b;
        b.setInputMethodMode(1);
    }
}
