package com.bumptech.glide.load.engine;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.animation.ValueAnimator;
import android.os.Handler;
import android.os.Message;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityManager;
import androidx.core.view.V;
import com.google.android.material.snackbar.BaseTransientBottomBar$Behavior;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class y implements Handler.Callback {
    public final /* synthetic */ int a;

    public /* synthetic */ y(int i) {
        this.a = i;
    }

    @Override // android.os.Handler.Callback
    public final boolean handleMessage(Message message) {
        List<AccessibilityServiceInfo> enabledAccessibilityServiceList;
        int i = 1;
        int i2 = 0;
        switch (this.a) {
            case 0:
                if (message.what != 1) {
                    return false;
                }
                ((v) message.obj).recycle();
                return true;
            case 1:
                if (message.what != 1) {
                    return false;
                }
                com.bumptech.glide.request.target.c cVar = (com.bumptech.glide.request.target.c) message.obj;
                cVar.d.i(cVar);
                return true;
            default:
                int i3 = message.what;
                if (i3 == 0) {
                    com.google.android.material.snackbar.g gVar = (com.google.android.material.snackbar.g) message.obj;
                    com.google.android.material.snackbar.f fVar = gVar.i;
                    if (fVar.getParent() == null) {
                        ViewGroup.LayoutParams layoutParams = fVar.getLayoutParams();
                        if (layoutParams instanceof androidx.coordinatorlayout.widget.e) {
                            androidx.coordinatorlayout.widget.e eVar = (androidx.coordinatorlayout.widget.e) layoutParams;
                            BaseTransientBottomBar$Behavior baseTransientBottomBar$Behavior = new BaseTransientBottomBar$Behavior();
                            com.google.android.gms.auth.api.signin.internal.h hVar = baseTransientBottomBar$Behavior.i;
                            hVar.getClass();
                            hVar.b = gVar.u;
                            baseTransientBottomBar$Behavior.b = new com.airbnb.lottie.network.d(gVar, 28);
                            eVar.b(baseTransientBottomBar$Behavior);
                            eVar.g = 80;
                        }
                        fVar.k = true;
                        gVar.g.addView(fVar);
                        fVar.k = false;
                        gVar.f();
                        fVar.setVisibility(4);
                    }
                    WeakHashMap weakHashMap = V.a;
                    if (fVar.isLaidOut()) {
                        gVar.e();
                        return true;
                    }
                    gVar.r = true;
                    return true;
                }
                if (i3 != 1) {
                    return false;
                }
                com.google.android.material.snackbar.g gVar2 = (com.google.android.material.snackbar.g) message.obj;
                int i4 = message.arg1;
                AccessibilityManager accessibilityManager = gVar2.t;
                if (accessibilityManager == null || ((enabledAccessibilityServiceList = accessibilityManager.getEnabledAccessibilityServiceList(1)) != null && enabledAccessibilityServiceList.isEmpty())) {
                    com.google.android.material.snackbar.f fVar2 = gVar2.i;
                    if (fVar2.getVisibility() == 0) {
                        if (fVar2.getAnimationMode() == 1) {
                            ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(1.0f, DefinitionKt.NO_Float_VALUE);
                            valueAnimatorOfFloat.setInterpolator(gVar2.d);
                            valueAnimatorOfFloat.addUpdateListener(new com.google.android.material.snackbar.b(gVar2, 0, (byte) 0));
                            valueAnimatorOfFloat.setDuration(gVar2.b);
                            valueAnimatorOfFloat.addListener(new com.google.android.material.snackbar.a(gVar2, i4, i2));
                            valueAnimatorOfFloat.start();
                            return true;
                        }
                        ValueAnimator valueAnimator = new ValueAnimator();
                        int height = fVar2.getHeight();
                        ViewGroup.LayoutParams layoutParams2 = fVar2.getLayoutParams();
                        if (layoutParams2 instanceof ViewGroup.MarginLayoutParams) {
                            height += ((ViewGroup.MarginLayoutParams) layoutParams2).bottomMargin;
                        }
                        valueAnimator.setIntValues(0, height);
                        valueAnimator.setInterpolator(gVar2.e);
                        valueAnimator.setDuration(gVar2.c);
                        valueAnimator.addListener(new com.google.android.material.snackbar.a(gVar2, i4, i));
                        valueAnimator.addUpdateListener(new com.google.android.material.snackbar.b(gVar2, 3, (byte) 0));
                        valueAnimator.start();
                        return true;
                    }
                }
                gVar2.c(i4);
                return true;
        }
    }
}
