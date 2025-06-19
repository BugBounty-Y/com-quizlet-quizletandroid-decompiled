package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.GradientDrawable;
import android.hardware.SensorManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_common.u;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class PXDoctorActivity extends I {
    public static final u e = new u(23);
    public static PXDoctorActivity f;
    public static com.perimeterx.mobile_sdk.doctor_app.state.d g;
    public static androidx.constraintlayout.core.widgets.analyzer.f h;
    public static com.braze.triggers.managers.h i;
    public static com.perimeterx.mobile_sdk.doctor_app.d j;
    public int b;
    public boolean c;
    public Fragment d;

    public static final void a(View view) {
        com.perimeterx.mobile_sdk.doctor_app.state.a aVarA;
        androidx.constraintlayout.core.widgets.analyzer.f fVar = h;
        if (fVar == null || fVar.b || (aVarA = ((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar.h).a().a()) == null) {
            return;
        }
        if (aVarA == com.perimeterx.mobile_sdk.doctor_app.state.a.a) {
            fVar.c = true;
        }
        fVar.b(aVarA);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        f = this;
        u uVar = e;
        Object systemService = getSystemService("sensor");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.hardware.SensorManager");
        SensorManager sensorManager = (SensorManager) systemService;
        Intrinsics.checkNotNullParameter(sensorManager, "sensorManager");
        com.perimeterx.mobile_sdk.extensions.a aVar = new com.perimeterx.mobile_sdk.extensions.a();
        aVar.a = uVar;
        sensorManager.registerListener(aVar, sensorManager.getDefaultSensor(1), 3);
        setContentView(R.layout.activity_px_doctor);
        ((TextView) findViewById(R.id.doctor_title_label)).setText("Doctor App");
        ((TextView) findViewById(R.id.doctor_credit_label)).setText("By PerimeterX");
        t();
        ImageButton imageButton = (ImageButton) findViewById(R.id.doctor_close_button);
        Resources resources = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        imageButton.setBackground(new BitmapDrawable(resources, ((C1721Kc) fVar.f).a("close_button_regular")));
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setCornerRadius(40.0f);
        gradientDrawable.setColor(-1);
        findViewById(R.id.doctor_content_view).setBackground(gradientDrawable);
        ImageButton imageButton2 = (ImageButton) findViewById(R.id.doctor_close_button);
        imageButton2.setOnClickListener(new com.braze.ui.inappmessage.f(1));
        imageButton2.setOnTouchListener(new com.braze.ui.a(3));
        View viewFindViewById = findViewById(R.id.doctor_popup_view);
        GradientDrawable gradientDrawable2 = new GradientDrawable();
        gradientDrawable2.setCornerRadius(40.0f);
        gradientDrawable2.setColor(getColor(R.color.DOCTOR_POPUP_BACKGROUND_COLOR));
        viewFindViewById.setBackground(gradientDrawable2);
        viewFindViewById.setVisibility(8);
        ((ImageView) findViewById(R.id.doctor_popup_thumbnail_image_view)).setVisibility(8);
        ((TextView) findViewById(R.id.doctor_popup_title_text_view)).setVisibility(8);
        ((TextView) findViewById(R.id.doctor_popup_message_text_view)).setVisibility(8);
        viewFindViewById.setOnTouchListener(new c(this));
        v();
        View rootView = findViewById(R.id.doctor_background_view).getRootView();
        rootView.setAlpha(DefinitionKt.NO_Float_VALUE);
        new Handler(Looper.getMainLooper()).postDelayed(new com.google.firebase.crashlytics.internal.common.i(13, rootView, this), 1000L);
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        f = null;
        super.onDestroy();
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public final void onPause() {
        androidx.constraintlayout.core.widgets.analyzer.f fVar;
        super.onPause();
        if (isFinishing()) {
            return;
        }
        this.c = false;
        int i2 = getResources().getConfiguration().orientation;
        int i3 = this.b;
        if (i3 != 0 && i3 != i2) {
            this.c = true;
        }
        this.b = i2;
        if (this.c || (fVar = h) == null) {
            return;
        }
        fVar.s();
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public final void onStop() {
        super.onStop();
        androidx.constraintlayout.core.widgets.analyzer.f fVar = h;
        if (fVar == null || fVar.c) {
            return;
        }
        com.perimeterx.mobile_sdk.doctor_app.model.c cVar = (com.perimeterx.mobile_sdk.doctor_app.model.c) fVar.h;
        if ((cVar.a() instanceof com.perimeterx.mobile_sdk.doctor_app.state.c) || (cVar.a() instanceof com.perimeterx.mobile_sdk.doctor_app.state.h)) {
            return;
        }
        fVar.s();
    }

    public final void q(boolean z, com.braze.triggers.managers.h hVar) {
        int height;
        float f2;
        F f3 = new F();
        View viewFindViewById = findViewById(R.id.doctor_background_view);
        View rootView = viewFindViewById.getRootView();
        ArrayList arrayListF = B.f(findViewById(R.id.doctor_content_view), findViewById(R.id.doctor_hide_bottom_corner_view), findViewById(R.id.doctor_close_button), findViewById(R.id.doctor_thumbnail), findViewById(R.id.doctor_title_label), findViewById(R.id.doctor_credit_label), findViewById(R.id.doctor_top_border_view), findViewById(R.id.doctor_fragment_container_view));
        int i2 = 0;
        if (z) {
            int height2 = rootView.getHeight();
            f2 = DefinitionKt.NO_Float_VALUE;
            i2 = height2;
            height = 0;
        } else {
            height = rootView.getHeight();
            f2 = 1.0f;
        }
        viewFindViewById.setAlpha(f2);
        Iterator it2 = arrayListF.iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (it2.hasNext()) {
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            ((View) next).setTranslationY(i2);
        }
        viewFindViewById.animate().setDuration(330L).alpha(1.0f - f2).setListener(null);
        Iterator it3 = arrayListF.iterator();
        Intrinsics.checkNotNullExpressionValue(it3, "iterator(...)");
        while (it3.hasNext()) {
            Object next2 = it3.next();
            Intrinsics.checkNotNullExpressionValue(next2, "next(...)");
            ((View) next2).animate().setDuration(330L).translationY(height).setListener(new b(f3, hVar));
        }
    }

    public final void r(boolean z, Function0 function0) {
        View viewFindViewById = findViewById(R.id.doctor_popup_view);
        ImageView imageView = (ImageView) findViewById(R.id.doctor_popup_thumbnail_image_view);
        TextView textView = (TextView) findViewById(R.id.doctor_popup_title_text_view);
        TextView textView2 = (TextView) findViewById(R.id.doctor_popup_message_text_view);
        float f2 = z ? 250.0f : DefinitionKt.NO_Float_VALUE;
        imageView.animate().setDuration(330L).translationY(f2);
        textView.animate().setDuration(330L).translationY(f2);
        textView2.animate().setDuration(330L).translationY(f2);
        viewFindViewById.animate().setDuration(330L).translationY(f2).setListener(new d(this, z, function0));
    }

    public final void t() {
        String str;
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        com.perimeterx.mobile_sdk.doctor_app.f fVar2 = (com.perimeterx.mobile_sdk.doctor_app.f) fVar.g;
        int i2 = fVar2 == null ? -1 : a.a[fVar2.ordinal()];
        String str2 = i2 != 1 ? i2 != 2 ? "px_thumbnail" : "account_defender_thumbnail" : "bot_defender_thumbnail";
        ImageView imageView = (ImageView) findViewById(R.id.doctor_thumbnail);
        androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar3);
        imageView.setImageBitmap(((C1721Kc) fVar3.f).a(str2));
        ImageView imageView2 = (ImageView) findViewById(R.id.doctor_popup_thumbnail_image_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar4 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar4);
        androidx.constraintlayout.core.widgets.analyzer.f fVar5 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar5);
        com.perimeterx.mobile_sdk.doctor_app.f fVar6 = (com.perimeterx.mobile_sdk.doctor_app.f) fVar5.g;
        if (fVar6 != null) {
            int iOrdinal = fVar6.ordinal();
            if (iOrdinal == 0) {
                str = "popup_bot_defender_thumbnail";
            } else {
                if (iOrdinal != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                str = "popup_account_defender_thumbnail";
            }
        } else {
            str = "popup_px_thumbnail";
        }
        imageView2.setImageBitmap(((C1721Kc) fVar4.f).a(str));
    }

    public final void v() {
        t();
        ImageButton imageButton = (ImageButton) findViewById(R.id.doctor_close_button);
        com.perimeterx.mobile_sdk.doctor_app.state.d dVar = g;
        if (dVar == null) {
            Intrinsics.m("state");
            throw null;
        }
        if (dVar.a() == null) {
            imageButton.setVisibility(8);
        } else {
            imageButton.setVisibility(0);
        }
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        supportFragmentManager.getClass();
        C1121a c1121a = new C1121a(supportFragmentManager);
        Intrinsics.checkNotNullExpressionValue(c1121a, "beginTransaction(...)");
        c1121a.p = true;
        Fragment fragment = this.d;
        if (fragment != null) {
            c1121a.k(fragment);
        }
        com.perimeterx.mobile_sdk.doctor_app.state.d dVar2 = g;
        if (dVar2 == null) {
            Intrinsics.m("state");
            throw null;
        }
        Fragment fragmentC = dVar2.c();
        this.d = fragmentC;
        c1121a.i(R.id.doctor_fragment_container_view, fragmentC, null, 1);
        c1121a.g();
    }
}
