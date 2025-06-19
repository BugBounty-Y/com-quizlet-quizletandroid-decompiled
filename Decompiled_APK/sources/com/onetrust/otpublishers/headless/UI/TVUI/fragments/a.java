package com.onetrust.otpublishers.headless.UI.TVUI.fragments;

import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.widget.NestedScrollView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public class a extends Fragment implements View.OnKeyListener, View.OnFocusChangeListener {
    public OTConfiguration A;
    public NestedScrollView B;
    public boolean C = true;
    public boolean D;
    public TextView a;
    public TextView b;
    public Button c;
    public Button d;
    public Button e;
    public I f;
    public com.onetrust.otpublishers.headless.UI.TVUI.datautils.a g;
    public g h;
    public LinearLayout i;
    public LinearLayout j;
    public LinearLayout k;
    public TextView l;
    public TextView m;
    public View n;
    public ImageView o;
    public ImageView p;
    public TextView q;
    public TextView r;
    public TextView s;
    public Button t;
    public Button u;
    public int v;
    public boolean w;
    public ImageView x;
    public LinearLayout y;
    public TextView z;

    public final void G(boolean z, androidx.constraintlayout.motion.widget.n nVar) {
        String str = (String) nVar.n;
        String str2 = (String) nVar.l;
        com.airbnb.lottie.animation.keyframe.q qVar = (com.airbnb.lottie.animation.keyframe.q) this.g.f;
        String str3 = (String) qVar.c;
        GradientDrawable gradientDrawableB = AbstractC3617f4.b(z, str, str2, str3 != null ? str3 : "#FFFFFF", (String) ((androidx.navigation.internal.m) qVar.g).b, this.o);
        if (!z) {
            this.o.getBackground().setTint(Color.parseColor((String) ((androidx.navigation.internal.m) ((com.airbnb.lottie.animation.keyframe.q) this.g.f).g).b));
            Drawable drawable = this.o.getDrawable();
            String str4 = (String) ((com.airbnb.lottie.animation.keyframe.q) this.g.f).c;
            drawable.setTint(Color.parseColor(str4 != null ? str4 : "#FFFFFF"));
        } else if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.l) && !com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.m)) {
            this.o.getBackground().setTint(Color.parseColor((String) nVar.l));
            this.o.getDrawable().setTint(Color.parseColor((String) nVar.m));
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
            return;
        }
        this.o.setBackground(gradientDrawableB);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setRetainInstance(true);
        this.f = getActivity();
    }

    /* JADX WARN: Removed duplicated region for block: B:48:0x0333 A[PHI: r0 r4
  0x0333: PHI (r0v191 android.widget.TextView) = (r0v190 android.widget.TextView), (r0v193 android.widget.TextView), (r0v194 android.widget.TextView) binds: [B:47:0x0331, B:44:0x031a, B:41:0x0303] A[DONT_GENERATE, DONT_INLINE]
  0x0333: PHI (r4v36 java.lang.String) = (r4v35 java.lang.String), (r4v38 java.lang.String), (r4v40 java.lang.String) binds: [B:47:0x0331, B:44:0x031a, B:41:0x0303] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:78:0x03d6  */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View onCreateView(android.view.LayoutInflater r18, android.view.ViewGroup r19, android.os.Bundle r20) {
        /*
            Method dump skipped, instructions count: 1596
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.a.onCreateView(android.view.LayoutInflater, android.view.ViewGroup, android.os.Bundle):android.view.View");
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        if (view.getId() == R.id.btn_accept_TV) {
            AbstractC3617f4.k(this.c, (androidx.constraintlayout.motion.widget.n) ((com.airbnb.lottie.animation.keyframe.q) this.g.f).k, z);
        }
        if (view.getId() == R.id.btn_reject_TV) {
            AbstractC3617f4.k(this.d, (androidx.constraintlayout.motion.widget.n) ((com.airbnb.lottie.animation.keyframe.q) this.g.f).l, z);
        }
        if (view.getId() == R.id.btn_mp_TV) {
            AbstractC3617f4.k(this.e, (androidx.constraintlayout.motion.widget.n) ((com.airbnb.lottie.animation.keyframe.q) this.g.f).m, z);
        }
        if (view.getId() == R.id.btn_VL_link_TV) {
            AbstractC3617f4.k(this.t, (androidx.constraintlayout.motion.widget.n) this.g.g, z);
        }
        if (view.getId() == R.id.tv_close_banner_text) {
            androidx.constraintlayout.motion.widget.n nVar = ((com.onetrust.otpublishers.headless.UI.Helper.c) this.g.e).s;
            if (AbstractC3605e0.a((String) nVar.k)) {
                AbstractC3617f4.k(this.u, nVar, z);
            } else {
                Button button = this.u;
                String strB = ((com.onetrust.otpublishers.headless.UI.Helper.c) this.g.e).b();
                if (z) {
                    AbstractC3617f4.k(button, nVar, true);
                    button.setPaintFlags(button.getPaintFlags() & (-9));
                } else {
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(strB)) {
                        button.setTextColor(Color.parseColor(strB));
                    }
                    button.setPaintFlags(button.getPaintFlags() | 8);
                    Drawable background = button.getBackground();
                    String str = (String) ((com.airbnb.lottie.animation.keyframe.q) this.g.f).c;
                    if (str == null) {
                        str = "#FFFFFF";
                    }
                    background.setTint(Color.parseColor(str));
                    button.setElevation(DefinitionKt.NO_Float_VALUE);
                }
            }
        }
        if (view.getId() == R.id.tv_close_banner) {
            G(z, (androidx.constraintlayout.motion.widget.n) ((com.airbnb.lottie.animation.keyframe.q) this.g.f).k);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:110:0x01e3 A[ADDED_TO_REGION, ORIG_RETURN, RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0176  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x017c  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01c4  */
    @Override // android.view.View.OnKeyListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean onKey(android.view.View r14, int r15, android.view.KeyEvent r16) {
        /*
            Method dump skipped, instructions count: 485
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.TVUI.fragments.a.onKey(android.view.View, int, android.view.KeyEvent):boolean");
    }
}
