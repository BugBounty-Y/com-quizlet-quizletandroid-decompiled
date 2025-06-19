package com.google.android.material.tabs;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.Layout;
import android.text.TextUtils;
import android.util.StateSet;
import android.view.LayoutInflater;
import android.view.PointerIcon;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.y1;
import androidx.core.view.N;
import androidx.core.view.V;
import com.google.android.material.internal.p;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class j extends LinearLayout {
    public static final /* synthetic */ int l = 0;
    public g a;
    public TextView b;
    public ImageView c;
    public View d;
    public com.google.android.material.badge.a e;
    public View f;
    public TextView g;
    public ImageView h;
    public Drawable i;
    public int j;
    public final /* synthetic */ l k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(l lVar, Context context) {
        super(context);
        this.k = lVar;
        this.j = 2;
        f(context);
        int i = lVar.e;
        WeakHashMap weakHashMap = V.a;
        setPaddingRelative(i, lVar.f, lVar.g, lVar.h);
        setGravity(17);
        setOrientation(!lVar.D ? 1 : 0);
        setClickable(true);
        N.a(this, PointerIcon.getSystemIcon(getContext(), 1002));
    }

    private com.google.android.material.badge.a getBadge() {
        return this.e;
    }

    @NonNull
    private com.google.android.material.badge.a getOrCreateBadge() {
        if (this.e == null) {
            this.e = new com.google.android.material.badge.a(getContext());
        }
        c();
        com.google.android.material.badge.a aVar = this.e;
        if (aVar != null) {
            return aVar;
        }
        throw new IllegalStateException("Unable to create badge");
    }

    public final void a(View view) {
        if (this.e == null || view == null) {
            return;
        }
        setClipChildren(false);
        setClipToPadding(false);
        ViewGroup viewGroup = (ViewGroup) getParent();
        if (viewGroup != null) {
            viewGroup.setClipChildren(false);
            viewGroup.setClipToPadding(false);
        }
        com.google.android.material.badge.a aVar = this.e;
        Rect rect = new Rect();
        view.getDrawingRect(rect);
        aVar.setBounds(rect);
        aVar.h(view, null);
        if (aVar.c() != null) {
            aVar.c().setForeground(aVar);
        } else {
            view.getOverlay().add(aVar);
        }
        this.d = view;
    }

    public final void b() {
        if (this.e != null) {
            setClipChildren(true);
            setClipToPadding(true);
            ViewGroup viewGroup = (ViewGroup) getParent();
            if (viewGroup != null) {
                viewGroup.setClipChildren(true);
                viewGroup.setClipToPadding(true);
            }
            View view = this.d;
            if (view != null) {
                com.google.android.material.badge.a aVar = this.e;
                if (aVar != null) {
                    if (aVar.c() != null) {
                        aVar.c().setForeground(null);
                    } else {
                        view.getOverlay().remove(aVar);
                    }
                }
                this.d = null;
            }
        }
    }

    public final void c() {
        g gVar;
        if (this.e != null) {
            if (this.f != null) {
                b();
                return;
            }
            ImageView imageView = this.c;
            if (imageView != null && (gVar = this.a) != null && gVar.b != null) {
                if (this.d == imageView) {
                    d(imageView);
                    return;
                } else {
                    b();
                    a(this.c);
                    return;
                }
            }
            TextView textView = this.b;
            if (textView == null || this.a == null) {
                b();
            } else if (this.d == textView) {
                d(textView);
            } else {
                b();
                a(this.b);
            }
        }
    }

    public final void d(View view) {
        com.google.android.material.badge.a aVar = this.e;
        if (aVar == null || view != this.d) {
            return;
        }
        Rect rect = new Rect();
        view.getDrawingRect(rect);
        aVar.setBounds(rect);
        aVar.h(view, null);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        int[] drawableState = getDrawableState();
        Drawable drawable = this.i;
        if ((drawable == null || !drawable.isStateful()) ? false : this.i.setState(drawableState)) {
            invalidate();
            this.k.invalidate();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0020  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e() {
        /*
            r3 = this;
            r3.g()
            com.google.android.material.tabs.g r0 = r3.a
            if (r0 == 0) goto L20
            com.google.android.material.tabs.l r1 = r0.g
            if (r1 == 0) goto L18
            int r1 = r1.getSelectedTabPosition()
            r2 = -1
            if (r1 == r2) goto L20
            int r0 = r0.e
            if (r1 != r0) goto L20
            r0 = 1
            goto L21
        L18:
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            java.lang.String r1 = "Tab not attached to a TabLayout"
            r0.<init>(r1)
            throw r0
        L20:
            r0 = 0
        L21:
            r3.setSelected(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.tabs.j.e():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v5, types: [android.graphics.drawable.RippleDrawable] */
    /* JADX WARN: Type inference failed for: r9v0, types: [android.view.View, com.google.android.material.tabs.j] */
    public final void f(Context context) {
        l lVar = this.k;
        int i = lVar.t;
        if (i != 0) {
            Drawable drawableF = com.facebook.appevents.g.f(context, i);
            this.i = drawableF;
            if (drawableF != null && drawableF.isStateful()) {
                this.i.setState(getDrawableState());
            }
        } else {
            this.i = null;
        }
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setColor(0);
        if (lVar.n != null) {
            GradientDrawable gradientDrawable2 = new GradientDrawable();
            gradientDrawable2.setCornerRadius(1.0E-5f);
            gradientDrawable2.setColor(-1);
            ColorStateList colorStateList = lVar.n;
            int[] iArr = com.google.android.material.ripple.a.d;
            int iA = com.google.android.material.ripple.a.a(colorStateList, com.google.android.material.ripple.a.c);
            int[] iArr2 = com.google.android.material.ripple.a.b;
            ColorStateList colorStateList2 = new ColorStateList(new int[][]{iArr, iArr2, StateSet.NOTHING}, new int[]{iA, com.google.android.material.ripple.a.a(colorStateList, iArr2), com.google.android.material.ripple.a.a(colorStateList, com.google.android.material.ripple.a.a)});
            boolean z = lVar.H;
            if (z) {
                gradientDrawable = null;
            }
            gradientDrawable = new RippleDrawable(colorStateList2, gradientDrawable, z ? null : gradientDrawable2);
        }
        WeakHashMap weakHashMap = V.a;
        setBackground(gradientDrawable);
        lVar.invalidate();
    }

    public final void g() {
        int i;
        ViewParent parent;
        g gVar = this.a;
        View view = gVar != null ? gVar.f : null;
        if (view != null) {
            ViewParent parent2 = view.getParent();
            if (parent2 != this) {
                if (parent2 != null) {
                    ((ViewGroup) parent2).removeView(view);
                }
                View view2 = this.f;
                if (view2 != null && (parent = view2.getParent()) != null) {
                    ((ViewGroup) parent).removeView(this.f);
                }
                addView(view);
            }
            this.f = view;
            TextView textView = this.b;
            if (textView != null) {
                textView.setVisibility(8);
            }
            ImageView imageView = this.c;
            if (imageView != null) {
                imageView.setVisibility(8);
                this.c.setImageDrawable(null);
            }
            TextView textView2 = (TextView) view.findViewById(R.id.text1);
            this.g = textView2;
            if (textView2 != null) {
                this.j = textView2.getMaxLines();
            }
            this.h = (ImageView) view.findViewById(R.id.icon);
        } else {
            View view3 = this.f;
            if (view3 != null) {
                removeView(view3);
                this.f = null;
            }
            this.g = null;
            this.h = null;
        }
        if (this.f == null) {
            if (this.c == null) {
                ImageView imageView2 = (ImageView) LayoutInflater.from(getContext()).inflate(com.quizlet.quizletandroid.R.layout.design_layout_tab_icon, (ViewGroup) this, false);
                this.c = imageView2;
                addView(imageView2, 0);
            }
            if (this.b == null) {
                TextView textView3 = (TextView) LayoutInflater.from(getContext()).inflate(com.quizlet.quizletandroid.R.layout.design_layout_tab_text, (ViewGroup) this, false);
                this.b = textView3;
                addView(textView3);
                this.j = this.b.getMaxLines();
            }
            TextView textView4 = this.b;
            l lVar = this.k;
            textView4.setTextAppearance(lVar.i);
            if (!isSelected() || (i = lVar.k) == -1) {
                this.b.setTextAppearance(lVar.j);
            } else {
                this.b.setTextAppearance(i);
            }
            ColorStateList colorStateList = lVar.l;
            if (colorStateList != null) {
                this.b.setTextColor(colorStateList);
            }
            h(this.b, this.c, true);
            c();
            ImageView imageView3 = this.c;
            if (imageView3 != null) {
                imageView3.addOnLayoutChangeListener(new i(this, imageView3));
            }
            TextView textView5 = this.b;
            if (textView5 != null) {
                textView5.addOnLayoutChangeListener(new i(this, textView5));
            }
        } else {
            TextView textView6 = this.g;
            if (textView6 != null || this.h != null) {
                h(textView6, this.h, false);
            }
        }
        if (gVar == null || TextUtils.isEmpty(gVar.d)) {
            return;
        }
        setContentDescription(gVar.d);
    }

    public int getContentHeight() {
        View[] viewArr = {this.b, this.c, this.f};
        int iMax = 0;
        int iMin = 0;
        boolean z = false;
        for (int i = 0; i < 3; i++) {
            View view = viewArr[i];
            if (view != null && view.getVisibility() == 0) {
                iMin = z ? Math.min(iMin, view.getTop()) : view.getTop();
                iMax = z ? Math.max(iMax, view.getBottom()) : view.getBottom();
                z = true;
            }
        }
        return iMax - iMin;
    }

    public int getContentWidth() {
        View[] viewArr = {this.b, this.c, this.f};
        int iMax = 0;
        int iMin = 0;
        boolean z = false;
        for (int i = 0; i < 3; i++) {
            View view = viewArr[i];
            if (view != null && view.getVisibility() == 0) {
                iMin = z ? Math.min(iMin, view.getLeft()) : view.getLeft();
                iMax = z ? Math.max(iMax, view.getRight()) : view.getRight();
                z = true;
            }
        }
        return iMax - iMin;
    }

    public g getTab() {
        return this.a;
    }

    public final void h(TextView textView, ImageView imageView, boolean z) {
        boolean z2;
        Drawable drawable;
        g gVar = this.a;
        Drawable drawableMutate = (gVar == null || (drawable = gVar.b) == null) ? null : drawable.mutate();
        l lVar = this.k;
        if (drawableMutate != null) {
            drawableMutate.setTintList(lVar.m);
            PorterDuff.Mode mode = lVar.q;
            if (mode != null) {
                drawableMutate.setTintMode(mode);
            }
        }
        g gVar2 = this.a;
        CharSequence charSequence = gVar2 != null ? gVar2.c : null;
        if (imageView != null) {
            if (drawableMutate != null) {
                imageView.setImageDrawable(drawableMutate);
                imageView.setVisibility(0);
                setVisibility(0);
            } else {
                imageView.setVisibility(8);
                imageView.setImageDrawable(null);
            }
        }
        boolean zIsEmpty = TextUtils.isEmpty(charSequence);
        if (textView != null) {
            if (zIsEmpty) {
                z2 = false;
            } else {
                this.a.getClass();
                z2 = true;
            }
            textView.setText(!zIsEmpty ? charSequence : null);
            textView.setVisibility(z2 ? 0 : 8);
            if (!zIsEmpty) {
                setVisibility(0);
            }
        } else {
            z2 = false;
        }
        if (z && imageView != null) {
            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) imageView.getLayoutParams();
            int iG = (z2 && imageView.getVisibility() == 0) ? (int) p.g(getContext(), 8) : 0;
            if (lVar.D) {
                if (iG != marginLayoutParams.getMarginEnd()) {
                    marginLayoutParams.setMarginEnd(iG);
                    marginLayoutParams.bottomMargin = 0;
                    imageView.setLayoutParams(marginLayoutParams);
                    imageView.requestLayout();
                }
            } else if (iG != marginLayoutParams.bottomMargin) {
                marginLayoutParams.bottomMargin = iG;
                marginLayoutParams.setMarginEnd(0);
                imageView.setLayoutParams(marginLayoutParams);
                imageView.requestLayout();
            }
        }
        g gVar3 = this.a;
        CharSequence charSequence2 = gVar3 != null ? gVar3.d : null;
        if (zIsEmpty) {
            charSequence = charSequence2;
        }
        y1.a(this, charSequence);
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0060  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onInitializeAccessibilityNodeInfo(android.view.accessibility.AccessibilityNodeInfo r8) {
        /*
            r7 = this;
            super.onInitializeAccessibilityNodeInfo(r8)
            com.google.android.material.badge.a r0 = r7.e
            r1 = 0
            r2 = 1
            if (r0 == 0) goto L80
            boolean r0 = r0.isVisible()
            if (r0 == 0) goto L80
            com.google.android.material.badge.a r0 = r7.e
            boolean r3 = r0.isVisible()
            r4 = 0
            if (r3 != 0) goto L1a
            goto L7d
        L1a:
            com.google.android.material.badge.b r3 = r0.e
            com.google.android.material.badge.BadgeState$State r3 = r3.b
            java.lang.String r5 = r3.j
            if (r5 == 0) goto L24
            r6 = r2
            goto L25
        L24:
            r6 = r1
        L25:
            if (r6 == 0) goto L2e
            java.lang.String r4 = r3.o
            if (r4 == 0) goto L2c
            goto L7d
        L2c:
            r4 = r5
            goto L7d
        L2e:
            boolean r5 = r0.f()
            if (r5 == 0) goto L7b
            int r5 = r3.q
            if (r5 == 0) goto L7d
            java.lang.ref.WeakReference r5 = r0.a
            java.lang.Object r5 = r5.get()
            android.content.Context r5 = (android.content.Context) r5
            if (r5 != 0) goto L43
            goto L7d
        L43:
            int r4 = r0.h
            r6 = -2
            if (r4 == r6) goto L60
            int r4 = r0.d()
            int r6 = r0.h
            if (r4 > r6) goto L51
            goto L60
        L51:
            int r0 = r3.r
            java.lang.Integer r3 = java.lang.Integer.valueOf(r6)
            java.lang.Object[] r3 = new java.lang.Object[]{r3}
            java.lang.String r4 = r5.getString(r0, r3)
            goto L7d
        L60:
            android.content.res.Resources r4 = r5.getResources()
            int r3 = r3.q
            int r5 = r0.d()
            int r0 = r0.d()
            java.lang.Integer r0 = java.lang.Integer.valueOf(r0)
            java.lang.Object[] r0 = new java.lang.Object[]{r0}
            java.lang.String r4 = r4.getQuantityString(r3, r5, r0)
            goto L7d
        L7b:
            java.lang.CharSequence r4 = r3.p
        L7d:
            r8.setContentDescription(r4)
        L80:
            com.google.android.material.tabs.g r0 = r7.a
            int r0 = r0.e
            boolean r3 = r7.isSelected()
            androidx.webkit.internal.p r0 = androidx.webkit.internal.p.r(r1, r2, r0, r2, r3)
            java.lang.Object r0 = r0.b
            android.view.accessibility.AccessibilityNodeInfo$CollectionItemInfo r0 = (android.view.accessibility.AccessibilityNodeInfo.CollectionItemInfo) r0
            r8.setCollectionItemInfo(r0)
            boolean r0 = r7.isSelected()
            if (r0 == 0) goto La5
            r8.setClickable(r1)
            androidx.core.view.accessibility.d r0 = androidx.core.view.accessibility.d.e
            java.lang.Object r0 = r0.a
            android.view.accessibility.AccessibilityNodeInfo$AccessibilityAction r0 = (android.view.accessibility.AccessibilityNodeInfo.AccessibilityAction) r0
            r8.removeAction(r0)
        La5:
            android.content.res.Resources r0 = r7.getResources()
            r1 = 2132018390(0x7f1404d6, float:1.9675085E38)
            java.lang.String r0 = r0.getString(r1)
            android.os.Bundle r8 = r8.getExtras()
            java.lang.String r1 = "AccessibilityNodeInfo.roleDescription"
            r8.putCharSequence(r1, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.tabs.j.onInitializeAccessibilityNodeInfo(android.view.accessibility.AccessibilityNodeInfo):void");
    }

    @Override // android.widget.LinearLayout, android.view.View
    public final void onMeasure(int i, int i2) {
        int size = View.MeasureSpec.getSize(i);
        int mode = View.MeasureSpec.getMode(i);
        l lVar = this.k;
        int tabMaxWidth = lVar.getTabMaxWidth();
        if (tabMaxWidth > 0 && (mode == 0 || size > tabMaxWidth)) {
            i = View.MeasureSpec.makeMeasureSpec(lVar.u, Integer.MIN_VALUE);
        }
        super.onMeasure(i, i2);
        if (this.b != null) {
            float f = lVar.r;
            int i3 = this.j;
            ImageView imageView = this.c;
            if (imageView == null || imageView.getVisibility() != 0) {
                TextView textView = this.b;
                if (textView != null && textView.getLineCount() > 1) {
                    f = lVar.s;
                }
            } else {
                i3 = 1;
            }
            float textSize = this.b.getTextSize();
            int lineCount = this.b.getLineCount();
            int maxLines = this.b.getMaxLines();
            if (f != textSize || (maxLines >= 0 && i3 != maxLines)) {
                if (lVar.C == 1 && f > textSize && lineCount == 1) {
                    Layout layout = this.b.getLayout();
                    if (layout == null) {
                        return;
                    }
                    if ((f / layout.getPaint().getTextSize()) * layout.getLineWidth(0) > (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight()) {
                        return;
                    }
                }
                this.b.setTextSize(0, f);
                this.b.setMaxLines(i3);
                super.onMeasure(i, i2);
            }
        }
    }

    @Override // android.view.View
    public final boolean performClick() {
        boolean zPerformClick = super.performClick();
        if (this.a == null) {
            return zPerformClick;
        }
        if (!zPerformClick) {
            playSoundEffect(0);
        }
        g gVar = this.a;
        l lVar = gVar.g;
        if (lVar == null) {
            throw new IllegalArgumentException("Tab not attached to a TabLayout");
        }
        lVar.m(gVar, true);
        return true;
    }

    @Override // android.view.View
    public void setSelected(boolean z) {
        isSelected();
        super.setSelected(z);
        TextView textView = this.b;
        if (textView != null) {
            textView.setSelected(z);
        }
        ImageView imageView = this.c;
        if (imageView != null) {
            imageView.setSelected(z);
        }
        View view = this.f;
        if (view != null) {
            view.setSelected(z);
        }
    }

    public void setTab(g gVar) {
        if (gVar != this.a) {
            this.a = gVar;
            e();
        }
    }
}
