package com.airbnb.lottie;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes.dex */
public class LottieAnimationView extends AppCompatImageView {
    public static final C1464d q = new C1464d();
    public final g d;
    public final g e;
    public x f;
    public int g;
    public final u h;
    public String i;
    public int j;
    public boolean k;
    public boolean l;
    public boolean m;
    public final HashSet n;
    public final HashSet o;
    public A p;

    public static class SavedState extends View.BaseSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new C1465e();
        public String a;
        public int b;
        public float c;
        public boolean d;
        public String e;
        public int f;
        public int g;

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeString(this.a);
            parcel.writeFloat(this.c);
            parcel.writeInt(this.d ? 1 : 0);
            parcel.writeString(this.e);
            parcel.writeInt(this.f);
            parcel.writeInt(this.g);
        }
    }

    public LottieAnimationView(Context context) {
        super(context);
        this.d = new g(this, 1);
        this.e = new g(this, 0);
        this.g = 0;
        this.h = new u();
        this.k = false;
        this.l = false;
        this.m = true;
        this.n = new HashSet();
        this.o = new HashSet();
        d(null);
    }

    private void setCompositionTask(A a) {
        z zVar = a.d;
        u uVar = this.h;
        if (zVar != null && uVar == getDrawable() && uVar.a == zVar.a) {
            return;
        }
        this.n.add(EnumC1466f.a);
        this.h.d();
        c();
        a.b(this.d);
        a.a(this.e);
        this.p = a;
    }

    public final void c() {
        A a = this.p;
        if (a != null) {
            g gVar = this.d;
            synchronized (a) {
                a.a.remove(gVar);
            }
            A a2 = this.p;
            g gVar2 = this.e;
            synchronized (a2) {
                a2.b.remove(gVar2);
            }
        }
    }

    public final void d(AttributeSet attributeSet) {
        String string;
        TypedArray typedArrayObtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, C.a, R.attr.lottieAnimationViewStyle, 0);
        this.m = typedArrayObtainStyledAttributes.getBoolean(4, true);
        boolean zHasValue = typedArrayObtainStyledAttributes.hasValue(16);
        boolean zHasValue2 = typedArrayObtainStyledAttributes.hasValue(11);
        boolean zHasValue3 = typedArrayObtainStyledAttributes.hasValue(21);
        if (zHasValue && zHasValue2) {
            throw new IllegalArgumentException("lottie_rawRes and lottie_fileName cannot be used at the same time. Please use only one at once.");
        }
        if (zHasValue) {
            int resourceId = typedArrayObtainStyledAttributes.getResourceId(16, 0);
            if (resourceId != 0) {
                setAnimation(resourceId);
            }
        } else if (zHasValue2) {
            String string2 = typedArrayObtainStyledAttributes.getString(11);
            if (string2 != null) {
                setAnimation(string2);
            }
        } else if (zHasValue3 && (string = typedArrayObtainStyledAttributes.getString(21)) != null) {
            setAnimationFromUrl(string);
        }
        setFallbackResource(typedArrayObtainStyledAttributes.getResourceId(10, 0));
        if (typedArrayObtainStyledAttributes.getBoolean(3, false)) {
            this.l = true;
        }
        boolean z = typedArrayObtainStyledAttributes.getBoolean(14, false);
        u uVar = this.h;
        if (z) {
            uVar.b.setRepeatCount(-1);
        }
        if (typedArrayObtainStyledAttributes.hasValue(19)) {
            setRepeatMode(typedArrayObtainStyledAttributes.getInt(19, 1));
        }
        if (typedArrayObtainStyledAttributes.hasValue(18)) {
            setRepeatCount(typedArrayObtainStyledAttributes.getInt(18, -1));
        }
        if (typedArrayObtainStyledAttributes.hasValue(20)) {
            setSpeed(typedArrayObtainStyledAttributes.getFloat(20, 1.0f));
        }
        if (typedArrayObtainStyledAttributes.hasValue(6)) {
            setClipToCompositionBounds(typedArrayObtainStyledAttributes.getBoolean(6, true));
        }
        if (typedArrayObtainStyledAttributes.hasValue(5)) {
            setClipTextToBoundingBox(typedArrayObtainStyledAttributes.getBoolean(5, false));
        }
        if (typedArrayObtainStyledAttributes.hasValue(8)) {
            setDefaultFontFileExtension(typedArrayObtainStyledAttributes.getString(8));
        }
        setImageAssetsFolder(typedArrayObtainStyledAttributes.getString(13));
        boolean zHasValue4 = typedArrayObtainStyledAttributes.hasValue(15);
        float f = typedArrayObtainStyledAttributes.getFloat(15, DefinitionKt.NO_Float_VALUE);
        if (zHasValue4) {
            this.n.add(EnumC1466f.b);
        }
        uVar.u(f);
        boolean z2 = typedArrayObtainStyledAttributes.getBoolean(9, false);
        v vVar = v.a;
        HashSet hashSet = (HashSet) uVar.l.b;
        boolean zAdd = z2 ? hashSet.add(vVar) : hashSet.remove(vVar);
        if (uVar.a != null && zAdd) {
            uVar.c();
        }
        setApplyingOpacityToLayersEnabled(typedArrayObtainStyledAttributes.getBoolean(0, false));
        setApplyingShadowToLayersEnabled(typedArrayObtainStyledAttributes.getBoolean(1, true));
        if (typedArrayObtainStyledAttributes.hasValue(7)) {
            uVar.a(new com.airbnb.lottie.model.e("**"), y.F, new com.quizlet.data.repository.widget.b(new E(androidx.core.content.c.c(getContext(), typedArrayObtainStyledAttributes.getResourceId(7, -1)).getDefaultColor(), PorterDuff.Mode.SRC_ATOP)));
        }
        if (typedArrayObtainStyledAttributes.hasValue(17)) {
            int i = typedArrayObtainStyledAttributes.getInt(17, 0);
            if (i >= D.values().length) {
                i = 0;
            }
            setRenderMode(D.values()[i]);
        }
        if (typedArrayObtainStyledAttributes.hasValue(2)) {
            int i2 = typedArrayObtainStyledAttributes.getInt(2, 0);
            if (i2 >= D.values().length) {
                i2 = 0;
            }
            setAsyncUpdates(EnumC1461a.values()[i2]);
        }
        setIgnoreDisabledSystemAnimations(typedArrayObtainStyledAttributes.getBoolean(12, false));
        if (typedArrayObtainStyledAttributes.hasValue(22)) {
            setUseCompositionFrameRate(typedArrayObtainStyledAttributes.getBoolean(22, false));
        }
        typedArrayObtainStyledAttributes.recycle();
    }

    public EnumC1461a getAsyncUpdates() {
        EnumC1461a enumC1461a = this.h.L;
        return enumC1461a != null ? enumC1461a : EnumC1461a.a;
    }

    public boolean getAsyncUpdatesEnabled() {
        EnumC1461a enumC1461a = this.h.L;
        if (enumC1461a == null) {
            enumC1461a = EnumC1461a.a;
        }
        return enumC1461a == EnumC1461a.b;
    }

    public boolean getClipTextToBoundingBox() {
        return this.h.u;
    }

    public boolean getClipToCompositionBounds() {
        return this.h.n;
    }

    public h getComposition() {
        Drawable drawable = getDrawable();
        u uVar = this.h;
        if (drawable == uVar) {
            return uVar.a;
        }
        return null;
    }

    public long getDuration() {
        h composition = getComposition();
        if (composition != null) {
            return (long) composition.b();
        }
        return 0L;
    }

    public int getFrame() {
        return (int) this.h.b.h;
    }

    public String getImageAssetsFolder() {
        return this.h.h;
    }

    public boolean getMaintainOriginalImageBounds() {
        return this.h.m;
    }

    public float getMaxFrame() {
        return this.h.b.c();
    }

    public float getMinFrame() {
        return this.h.b.d();
    }

    public B getPerformanceTracker() {
        h hVar = this.h.a;
        if (hVar != null) {
            return hVar.a;
        }
        return null;
    }

    public float getProgress() {
        return this.h.b.b();
    }

    public D getRenderMode() {
        return this.h.w ? D.c : D.b;
    }

    public int getRepeatCount() {
        return this.h.b.getRepeatCount();
    }

    public int getRepeatMode() {
        return this.h.b.getRepeatMode();
    }

    public float getSpeed() {
        return this.h.b.d;
    }

    @Override // android.view.View
    public final void invalidate() {
        super.invalidate();
        Drawable drawable = getDrawable();
        if (drawable instanceof u) {
            boolean z = ((u) drawable).w;
            D d = D.c;
            if ((z ? d : D.b) == d) {
                this.h.invalidateSelf();
            }
        }
    }

    @Override // android.widget.ImageView, android.view.View, android.graphics.drawable.Drawable.Callback
    public final void invalidateDrawable(Drawable drawable) {
        Drawable drawable2 = getDrawable();
        u uVar = this.h;
        if (drawable2 == uVar) {
            super.invalidateDrawable(uVar);
        } else {
            super.invalidateDrawable(drawable);
        }
    }

    @Override // android.widget.ImageView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (isInEditMode() || !this.l) {
            return;
        }
        this.h.k();
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        int i;
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.getSuperState());
        this.i = savedState.a;
        EnumC1466f enumC1466f = EnumC1466f.a;
        HashSet hashSet = this.n;
        if (!hashSet.contains(enumC1466f) && !TextUtils.isEmpty(this.i)) {
            setAnimation(this.i);
        }
        this.j = savedState.b;
        if (!hashSet.contains(enumC1466f) && (i = this.j) != 0) {
            setAnimation(i);
        }
        boolean zContains = hashSet.contains(EnumC1466f.b);
        u uVar = this.h;
        if (!zContains) {
            uVar.u(savedState.c);
        }
        EnumC1466f enumC1466f2 = EnumC1466f.f;
        if (!hashSet.contains(enumC1466f2) && savedState.d) {
            hashSet.add(enumC1466f2);
            uVar.k();
        }
        if (!hashSet.contains(EnumC1466f.e)) {
            setImageAssetsFolder(savedState.e);
        }
        if (!hashSet.contains(EnumC1466f.c)) {
            setRepeatMode(savedState.f);
        }
        if (hashSet.contains(EnumC1466f.d)) {
            return;
        }
        setRepeatCount(savedState.g);
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        boolean z;
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        savedState.a = this.i;
        savedState.b = this.j;
        u uVar = this.h;
        savedState.c = uVar.b.b();
        boolean zIsVisible = uVar.isVisible();
        com.airbnb.lottie.utils.e eVar = uVar.b;
        if (zIsVisible) {
            z = eVar.m;
        } else {
            int i = uVar.X;
            z = i == 2 || i == 3;
        }
        savedState.d = z;
        savedState.e = uVar.h;
        savedState.f = eVar.getRepeatMode();
        savedState.g = eVar.getRepeatCount();
        return savedState;
    }

    public void setAnimation(int i) {
        A aF;
        this.j = i;
        this.i = null;
        if (isInEditMode()) {
            aF = new A(new androidx.work.impl.utils.e(this, i, 1), true);
        } else if (this.m) {
            Context context = getContext();
            aF = l.f(context, l.l(context, i), i);
        } else {
            aF = l.f(getContext(), null, i);
        }
        setCompositionTask(aF);
    }

    @Deprecated
    public void setAnimationFromJson(String str) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(str.getBytes());
        setCompositionTask(l.a(null, new androidx.work.impl.utils.d(byteArrayInputStream, 2), new androidx.compose.ui.text.input.C(byteArrayInputStream, 10)));
    }

    public void setAnimationFromUrl(String str) {
        A a;
        int i = 0;
        String str2 = null;
        if (this.m) {
            Context context = getContext();
            HashMap map = l.a;
            String strD = AbstractC0147y.d("url_", str);
            a = l.a(strD, new i(context, str, strD, i), null);
        } else {
            a = l.a(null, new i(getContext(), str, str2, i), null);
        }
        setCompositionTask(a);
    }

    public void setApplyingOpacityToLayersEnabled(boolean z) {
        this.h.s = z;
    }

    public void setApplyingShadowToLayersEnabled(boolean z) {
        this.h.t = z;
    }

    public void setAsyncUpdates(EnumC1461a enumC1461a) {
        this.h.L = enumC1461a;
    }

    public void setCacheComposition(boolean z) {
        this.m = z;
    }

    public void setClipTextToBoundingBox(boolean z) {
        u uVar = this.h;
        if (z != uVar.u) {
            uVar.u = z;
            uVar.invalidateSelf();
        }
    }

    public void setClipToCompositionBounds(boolean z) {
        u uVar = this.h;
        if (z != uVar.n) {
            uVar.n = z;
            com.airbnb.lottie.model.layer.c cVar = uVar.o;
            if (cVar != null) {
                cVar.L = z;
            }
            uVar.invalidateSelf();
        }
    }

    public void setComposition(@NonNull h hVar) {
        u uVar = this.h;
        uVar.setCallback(this);
        this.k = true;
        boolean zN = uVar.n(hVar);
        if (this.l) {
            uVar.k();
        }
        this.k = false;
        if (getDrawable() != uVar || zN) {
            if (!zN) {
                com.airbnb.lottie.utils.e eVar = uVar.b;
                boolean z = eVar != null ? eVar.m : false;
                setImageDrawable(null);
                setImageDrawable(uVar);
                if (z) {
                    uVar.m();
                }
            }
            onVisibilityChanged(this, getVisibility());
            requestLayout();
            Iterator it2 = this.o.iterator();
            if (it2.hasNext()) {
                throw android.support.v4.media.session.a.d(it2);
            }
        }
    }

    public void setDefaultFontFileExtension(String str) {
        u uVar = this.h;
        uVar.k = str;
        com.quizlet.data.interactor.folderwithcreator.m mVarI = uVar.i();
        if (mVarI != null) {
            mVarI.e = str;
        }
    }

    public void setFailureListener(x xVar) {
        this.f = xVar;
    }

    public void setFallbackResource(int i) {
        this.g = i;
    }

    public void setFontAssetDelegate(AbstractC1462b abstractC1462b) {
        com.quizlet.data.interactor.folderwithcreator.m mVar = this.h.i;
    }

    public void setFontMap(Map<String, Typeface> map) {
        u uVar = this.h;
        if (map == uVar.j) {
            return;
        }
        uVar.j = map;
        uVar.invalidateSelf();
    }

    public void setFrame(int i) {
        this.h.o(i);
    }

    @Deprecated
    public void setIgnoreDisabledSystemAnimations(boolean z) {
        this.h.d = z;
    }

    public void setImageAssetDelegate(InterfaceC1463c interfaceC1463c) {
        com.airbnb.lottie.manager.a aVar = this.h.g;
    }

    public void setImageAssetsFolder(String str) {
        this.h.h = str;
    }

    @Override // androidx.appcompat.widget.AppCompatImageView, android.widget.ImageView
    public void setImageBitmap(Bitmap bitmap) {
        this.j = 0;
        this.i = null;
        c();
        super.setImageBitmap(bitmap);
    }

    @Override // androidx.appcompat.widget.AppCompatImageView, android.widget.ImageView
    public void setImageDrawable(Drawable drawable) {
        this.j = 0;
        this.i = null;
        c();
        super.setImageDrawable(drawable);
    }

    @Override // androidx.appcompat.widget.AppCompatImageView, android.widget.ImageView
    public void setImageResource(int i) {
        this.j = 0;
        this.i = null;
        c();
        super.setImageResource(i);
    }

    public void setMaintainOriginalImageBounds(boolean z) {
        this.h.m = z;
    }

    public void setMaxFrame(int i) {
        this.h.p(i);
    }

    public void setMaxProgress(float f) {
        u uVar = this.h;
        h hVar = uVar.a;
        if (hVar == null) {
            uVar.f.add(new p(uVar, f, 0));
            return;
        }
        float f2 = com.airbnb.lottie.utils.g.f(hVar.l, hVar.m, f);
        com.airbnb.lottie.utils.e eVar = uVar.b;
        eVar.k(eVar.j, f2);
    }

    public void setMinAndMaxFrame(String str) {
        this.h.r(str);
    }

    public void setMinFrame(int i) {
        this.h.s(i);
    }

    public void setMinProgress(float f) {
        u uVar = this.h;
        h hVar = uVar.a;
        if (hVar == null) {
            uVar.f.add(new p(uVar, f, 1));
        } else {
            uVar.s((int) com.airbnb.lottie.utils.g.f(hVar.l, hVar.m, f));
        }
    }

    public void setOutlineMasksAndMattes(boolean z) {
        u uVar = this.h;
        if (uVar.r == z) {
            return;
        }
        uVar.r = z;
        com.airbnb.lottie.model.layer.c cVar = uVar.o;
        if (cVar != null) {
            cVar.q(z);
        }
    }

    public void setPerformanceTrackingEnabled(boolean z) {
        u uVar = this.h;
        uVar.q = z;
        h hVar = uVar.a;
        if (hVar != null) {
            hVar.a.a = z;
        }
    }

    public void setProgress(float f) {
        this.n.add(EnumC1466f.b);
        this.h.u(f);
    }

    public void setRenderMode(D d) {
        u uVar = this.h;
        uVar.v = d;
        uVar.e();
    }

    public void setRepeatCount(int i) {
        this.n.add(EnumC1466f.d);
        this.h.b.setRepeatCount(i);
    }

    public void setRepeatMode(int i) {
        this.n.add(EnumC1466f.c);
        this.h.b.setRepeatMode(i);
    }

    public void setSafeMode(boolean z) {
        this.h.e = z;
    }

    public void setSpeed(float f) {
        this.h.b.d = f;
    }

    public void setTextDelegate(F f) {
        this.h.getClass();
    }

    public void setUseCompositionFrameRate(boolean z) {
        this.h.b.n = z;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0019  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void unscheduleDrawable(android.graphics.drawable.Drawable r5) {
        /*
            r4 = this;
            boolean r0 = r4.k
            r1 = 0
            if (r0 != 0) goto L19
            com.airbnb.lottie.u r2 = r4.h
            if (r5 != r2) goto L19
            com.airbnb.lottie.utils.e r3 = r2.b
            if (r3 != 0) goto Lf
            r3 = r1
            goto L11
        Lf:
            boolean r3 = r3.m
        L11:
            if (r3 == 0) goto L19
            r4.l = r1
            r2.j()
            goto L2e
        L19:
            if (r0 != 0) goto L2e
            boolean r0 = r5 instanceof com.airbnb.lottie.u
            if (r0 == 0) goto L2e
            r0 = r5
            com.airbnb.lottie.u r0 = (com.airbnb.lottie.u) r0
            com.airbnb.lottie.utils.e r2 = r0.b
            if (r2 != 0) goto L27
            goto L29
        L27:
            boolean r1 = r2.m
        L29:
            if (r1 == 0) goto L2e
            r0.j()
        L2e:
            super.unscheduleDrawable(r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.LottieAnimationView.unscheduleDrawable(android.graphics.drawable.Drawable):void");
    }

    public void setMaxFrame(String str) {
        this.h.q(str);
    }

    public void setMinFrame(String str) {
        this.h.t(str);
    }

    public void setAnimation(String str) {
        A a;
        int i = 1;
        this.i = str;
        this.j = 0;
        if (isInEditMode()) {
            a = new A(new androidx.work.impl.A(i, this, str), true);
        } else {
            String str2 = null;
            if (this.m) {
                Context context = getContext();
                HashMap map = l.a;
                String strD = AbstractC0147y.d("asset_", str);
                a = l.a(strD, new i(context.getApplicationContext(), str, strD, i), null);
            } else {
                Context context2 = getContext();
                HashMap map2 = l.a;
                a = l.a(null, new i(context2.getApplicationContext(), str, str2, i), null);
            }
        }
        setCompositionTask(a);
    }

    public LottieAnimationView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.d = new g(this, 1);
        this.e = new g(this, 0);
        this.g = 0;
        this.h = new u();
        this.k = false;
        this.l = false;
        this.m = true;
        this.n = new HashSet();
        this.o = new HashSet();
        d(attributeSet);
    }
}
