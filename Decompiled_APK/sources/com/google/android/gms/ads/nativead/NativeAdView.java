package com.google.android.gms.ads.nativead;

import android.content.Context;
import android.os.RemoteException;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.webkit.internal.p;
import com.google.android.gms.ads.internal.client.C1606m;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.F0;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.ads.m;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C8;

/* loaded from: classes2.dex */
public final class NativeAdView extends FrameLayout {
    public final FrameLayout a;
    public final C8 b;

    public NativeAdView(@NonNull Context context) {
        super(context);
        FrameLayout frameLayout = new FrameLayout(context);
        frameLayout.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        addView(frameLayout);
        this.a = frameLayout;
        this.b = c();
    }

    public static void b(NativeAdView nativeAdView, m mVar) {
        C8 c8 = nativeAdView.b;
        if (c8 == null) {
            return;
        }
        try {
            if (mVar instanceof F0) {
                c8.q1(((F0) mVar).a);
            } else if (mVar == null) {
                c8.q1(null);
            } else {
                i.d("Use MediaContent provided by NativeAd.getMediaContent");
            }
        } catch (RemoteException e) {
            i.f("Unable to call setMediaContent on delegate", e);
        }
    }

    public final View a(String str) {
        C8 c8 = this.b;
        if (c8 == null) {
            return null;
        }
        try {
            com.google.android.gms.dynamic.a aVarC = c8.C(str);
            if (aVarC != null) {
                return (View) com.google.android.gms.dynamic.b.I3(aVarC);
            }
            return null;
        } catch (RemoteException e) {
            i.f("Unable to call getAssetView on delegate", e);
            return null;
        }
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i, ViewGroup.LayoutParams layoutParams) {
        super.addView(view, i, layoutParams);
        super.bringChildToFront(this.a);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void bringChildToFront(View view) {
        super.bringChildToFront(view);
        FrameLayout frameLayout = this.a;
        if (frameLayout != view) {
            super.bringChildToFront(frameLayout);
        }
    }

    public final C8 c() {
        if (isInEditMode()) {
            return null;
        }
        C1608n c1608n = C1614q.f.b;
        FrameLayout frameLayout = this.a;
        Context context = frameLayout.getContext();
        c1608n.getClass();
        return (C8) new C1606m(c1608n, this, frameLayout, context).d(context, false);
    }

    public final void d(View view, String str) {
        C8 c8 = this.b;
        if (c8 == null) {
            return;
        }
        try {
            c8.y2(new com.google.android.gms.dynamic.b(view), str);
        } catch (RemoteException e) {
            i.f("Unable to call setAssetView on delegate", e);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchTouchEvent(MotionEvent motionEvent) {
        C8 c8 = this.b;
        if (c8 != null) {
            if (((Boolean) r.d.c.a(AbstractC2773w7.zb)).booleanValue()) {
                try {
                    c8.Y2(new com.google.android.gms.dynamic.b(motionEvent));
                } catch (RemoteException e) {
                    i.f("Unable to call handleTouchEvent on delegate", e);
                }
            }
        }
        return super.dispatchTouchEvent(motionEvent);
    }

    public a getAdChoicesView() {
        View viewA = a("3011");
        if (viewA instanceof a) {
            return (a) viewA;
        }
        return null;
    }

    public final View getAdvertiserView() {
        return a("3005");
    }

    public final View getBodyView() {
        return a("3004");
    }

    public final View getCallToActionView() {
        return a("3002");
    }

    public final View getHeadlineView() {
        return a("3001");
    }

    public final View getIconView() {
        return a("3003");
    }

    public final View getImageView() {
        return a("3008");
    }

    public final b getMediaView() {
        View viewA = a("3010");
        if (viewA instanceof b) {
            return (b) viewA;
        }
        if (viewA == null) {
            return null;
        }
        i.d("View is not an instance of MediaView");
        return null;
    }

    public final View getPriceView() {
        return a("3007");
    }

    public final View getStarRatingView() {
        return a("3009");
    }

    public final View getStoreView() {
        return a("3006");
    }

    @Override // android.view.View
    public final void onVisibilityChanged(View view, int i) {
        super.onVisibilityChanged(view, i);
        C8 c8 = this.b;
        if (c8 == null) {
            return;
        }
        try {
            c8.V3(new com.google.android.gms.dynamic.b(view), i);
        } catch (RemoteException e) {
            i.f("Unable to call onVisibilityChanged on delegate", e);
        }
    }

    @Override // android.view.ViewGroup
    public final void removeAllViews() {
        super.removeAllViews();
        addView(this.a);
    }

    @Override // android.view.ViewGroup, android.view.ViewManager
    public final void removeView(View view) {
        if (this.a == view) {
            return;
        }
        super.removeView(view);
    }

    public void setAdChoicesView(a aVar) {
        d(aVar, "3011");
    }

    public final void setAdvertiserView(View view) {
        d(view, "3005");
    }

    public final void setBodyView(View view) {
        d(view, "3004");
    }

    public final void setCallToActionView(View view) {
        d(view, "3002");
    }

    public final void setClickConfirmingView(View view) {
        C8 c8 = this.b;
        if (c8 == null) {
            return;
        }
        try {
            c8.K0(new com.google.android.gms.dynamic.b(view));
        } catch (RemoteException e) {
            i.f("Unable to call setClickConfirmingView on delegate", e);
        }
    }

    public final void setHeadlineView(View view) {
        d(view, "3001");
    }

    public final void setIconView(View view) {
        d(view, "3003");
    }

    public final void setImageView(View view) {
        d(view, "3008");
    }

    public final void setMediaView(b bVar) {
        d(bVar, "3010");
        if (bVar == null) {
            return;
        }
        p pVar = new p(this, 16);
        synchronized (bVar) {
            bVar.e = pVar;
            if (bVar.b) {
                b(this, bVar.a);
            }
        }
        com.airbnb.lottie.network.c cVar = new com.airbnb.lottie.network.c(this, 19);
        synchronized (bVar) {
            bVar.f = cVar;
            if (bVar.d) {
                ImageView.ScaleType scaleType = bVar.c;
                C8 c8 = this.b;
                if (c8 != null && scaleType != null) {
                    try {
                        c8.m2(new com.google.android.gms.dynamic.b(scaleType));
                    } catch (RemoteException e) {
                        i.f("Unable to call setMediaViewImageScaleType on delegate", e);
                    }
                }
            }
        }
    }

    public void setNativeAd(@NonNull NativeAd nativeAd) {
        C8 c8 = this.b;
        if (c8 == null) {
            return;
        }
        try {
            c8.D2(nativeAd.d());
        } catch (RemoteException e) {
            i.f("Unable to call setNativeAd on delegate", e);
        }
    }

    public final void setPriceView(View view) {
        d(view, "3007");
    }

    public final void setStarRatingView(View view) {
        d(view, "3009");
    }

    public final void setStoreView(View view) {
        d(view, "3006");
    }

    public NativeAdView(@NonNull Context context, @NonNull AttributeSet attributeSet) {
        super(context, attributeSet);
        FrameLayout frameLayout = new FrameLayout(context);
        frameLayout.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        addView(frameLayout);
        this.a = frameLayout;
        this.b = c();
    }
}
