package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.animation.Animator;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.measurement.internal.A0;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements Animator.AnimatorListener {
    public final /* synthetic */ PXDoctorActivity a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Function0 c;

    public d(PXDoctorActivity pXDoctorActivity, boolean z, Function0 function0) {
        this.a = pXDoctorActivity;
        this.b = z;
        this.c = function0;
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationCancel(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation, boolean z) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationRepeat(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation) {
        Intrinsics.checkNotNullParameter(animation, "animation");
        u uVar = PXDoctorActivity.e;
        PXDoctorActivity pXDoctorActivity = this.a;
        View viewFindViewById = pXDoctorActivity.findViewById(R.id.doctor_popup_view);
        ImageView imageView = (ImageView) pXDoctorActivity.findViewById(R.id.doctor_popup_thumbnail_image_view);
        TextView textView = (TextView) pXDoctorActivity.findViewById(R.id.doctor_popup_title_text_view);
        TextView textView2 = (TextView) pXDoctorActivity.findViewById(R.id.doctor_popup_message_text_view);
        Function0 function0 = this.c;
        if (this.b) {
            new Handler(Looper.getMainLooper()).postDelayed(new A0(pXDoctorActivity, false, function0, 13), 2000L);
            return;
        }
        viewFindViewById.setVisibility(8);
        imageView.setVisibility(8);
        textView.setVisibility(8);
        textView2.setVisibility(8);
        function0.invoke();
    }

    @Override // android.animation.Animator.AnimatorListener
    public final void onAnimationStart(Animator animation, boolean z) {
        Intrinsics.checkNotNullParameter(animation, "animation");
    }
}
