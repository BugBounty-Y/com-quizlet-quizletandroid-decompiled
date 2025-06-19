package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.content.Context;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_common.V3;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public abstract class a {
    public final Context a;
    public final ExtendedFloatingActionButton b;
    public final ArrayList c = new ArrayList();
    public final com.airbnb.lottie.network.d d;
    public com.google.android.material.animation.f e;
    public com.google.android.material.animation.f f;

    public a(ExtendedFloatingActionButton extendedFloatingActionButton, com.airbnb.lottie.network.d dVar) {
        this.b = extendedFloatingActionButton;
        this.a = extendedFloatingActionButton.getContext();
        this.d = dVar;
    }

    public AnimatorSet a() {
        com.google.android.material.animation.f fVar = this.f;
        if (fVar == null) {
            if (this.e == null) {
                this.e = com.google.android.material.animation.f.b(this.a, c());
            }
            fVar = this.e;
            fVar.getClass();
        }
        return b(fVar);
    }

    public final AnimatorSet b(com.google.android.material.animation.f fVar) {
        ArrayList arrayList = new ArrayList();
        boolean zG = fVar.g("opacity");
        ExtendedFloatingActionButton extendedFloatingActionButton = this.b;
        if (zG) {
            arrayList.add(fVar.d("opacity", extendedFloatingActionButton, View.ALPHA));
        }
        if (fVar.g("scale")) {
            arrayList.add(fVar.d("scale", extendedFloatingActionButton, View.SCALE_Y));
            arrayList.add(fVar.d("scale", extendedFloatingActionButton, View.SCALE_X));
        }
        if (fVar.g(OTUXParamsKeys.OT_UX_WIDTH)) {
            arrayList.add(fVar.d(OTUXParamsKeys.OT_UX_WIDTH, extendedFloatingActionButton, ExtendedFloatingActionButton.I));
        }
        if (fVar.g(OTUXParamsKeys.OT_UX_HEIGHT)) {
            arrayList.add(fVar.d(OTUXParamsKeys.OT_UX_HEIGHT, extendedFloatingActionButton, ExtendedFloatingActionButton.J));
        }
        if (fVar.g("paddingStart")) {
            arrayList.add(fVar.d("paddingStart", extendedFloatingActionButton, ExtendedFloatingActionButton.K));
        }
        if (fVar.g("paddingEnd")) {
            arrayList.add(fVar.d("paddingEnd", extendedFloatingActionButton, ExtendedFloatingActionButton.L));
        }
        if (fVar.g("labelOpacity")) {
            arrayList.add(fVar.d("labelOpacity", extendedFloatingActionButton, new com.google.android.material.animation.e(this)));
        }
        AnimatorSet animatorSet = new AnimatorSet();
        V3.b(animatorSet, arrayList);
        return animatorSet;
    }

    public abstract int c();

    public void d() {
        this.d.b = null;
    }

    public abstract void e();

    public abstract void f(Animator animator);

    public abstract void g();

    public abstract boolean h();
}
