package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C4;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class q extends Fragment {
    public static void G(PXDoctorActivity pXDoctorActivity, View view, Button button, Button button2, Function0 function0) throws Resources.NotFoundException {
        ((Button) view.findViewById(R.id.doctor_test_selection_native_button)).setEnabled(false);
        ((Button) view.findViewById(R.id.doctor_test_selection_web_view_button)).setEnabled(false);
        ((Button) view.findViewById(R.id.doctor_test_selection_continue_to_test_result_button)).setEnabled(false);
        try {
            float f = 8000 * pXDoctorActivity.getResources().getDisplayMetrics().density;
            button.setCameraDistance(f);
            button2.setCameraDistance(f);
            Animator animatorLoadAnimator = AnimatorInflater.loadAnimator(pXDoctorActivity, R.anim.doctor_flip_out);
            animatorLoadAnimator.setTarget(button2);
            Animator animatorLoadAnimator2 = AnimatorInflater.loadAnimator(pXDoctorActivity, R.anim.doctor_flip_in);
            animatorLoadAnimator2.setTarget(button);
            animatorLoadAnimator.start();
            animatorLoadAnimator2.start();
            animatorLoadAnimator2.addListener(new n(function0));
        } catch (Exception unused) {
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        final int i = 0;
        final View viewInflate = inflater.inflate(R.layout.fragment_px_doctor_test_selection, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        TextView textView = (TextView) viewInflate.findViewById(R.id.doctor_test_selection_remember_text_view);
        textView.setText("Shake your device at any time for help, or see instructions.");
        int i2 = androidx.compose.ui.text.platform.e.c;
        C4.a(textView, "instructions", new com.braze.ui.inappmessage.listeners.a(28));
        Button button = (Button) viewInflate.findViewById(R.id.doctor_test_selection_native_button);
        button.setText("START");
        final int i3 = 1;
        button.setOnClickListener(new View.OnClickListener(this) { // from class: com.perimeterx.mobile_sdk.doctor_app.ui.o
            public final /* synthetic */ q b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws Resources.NotFoundException {
                switch (i3) {
                    case 0:
                        this.b.getClass();
                        View view2 = viewInflate;
                        Button button2 = (Button) view2.findViewById(R.id.doctor_test_selection_web_view_button);
                        Button button3 = (Button) view2.findViewById(R.id.doctor_test_selection_web_view_fake_button);
                        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
                        Intrinsics.d(pXDoctorActivity);
                        Intrinsics.d(button3);
                        Intrinsics.d(button2);
                        q.G(pXDoctorActivity, view2, button3, button2, new p(0));
                        break;
                    default:
                        this.b.getClass();
                        View view3 = viewInflate;
                        Button button4 = (Button) view3.findViewById(R.id.doctor_test_selection_native_button);
                        Button button5 = (Button) view3.findViewById(R.id.doctor_test_selection_native_fake_button);
                        PXDoctorActivity pXDoctorActivity2 = PXDoctorActivity.f;
                        Intrinsics.d(pXDoctorActivity2);
                        Intrinsics.d(button5);
                        Intrinsics.d(button4);
                        q.G(pXDoctorActivity2, view3, button5, button4, new com.braze.ui.inappmessage.listeners.a(29));
                        break;
                }
            }
        });
        button.setOnTouchListener(new com.braze.ui.a(15));
        ((Button) viewInflate.findViewById(R.id.doctor_test_selection_native_fake_button)).setText("TESTING");
        ((TextView) viewInflate.findViewById(R.id.doctor_test_selection_native_text_view)).setText("Native app framework");
        Button button2 = (Button) viewInflate.findViewById(R.id.doctor_test_selection_web_view_button);
        button2.setText("START");
        button2.setOnClickListener(new View.OnClickListener(this) { // from class: com.perimeterx.mobile_sdk.doctor_app.ui.o
            public final /* synthetic */ q b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) throws Resources.NotFoundException {
                switch (i) {
                    case 0:
                        this.b.getClass();
                        View view2 = viewInflate;
                        Button button22 = (Button) view2.findViewById(R.id.doctor_test_selection_web_view_button);
                        Button button3 = (Button) view2.findViewById(R.id.doctor_test_selection_web_view_fake_button);
                        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
                        Intrinsics.d(pXDoctorActivity);
                        Intrinsics.d(button3);
                        Intrinsics.d(button22);
                        q.G(pXDoctorActivity, view2, button3, button22, new p(0));
                        break;
                    default:
                        this.b.getClass();
                        View view3 = viewInflate;
                        Button button4 = (Button) view3.findViewById(R.id.doctor_test_selection_native_button);
                        Button button5 = (Button) view3.findViewById(R.id.doctor_test_selection_native_fake_button);
                        PXDoctorActivity pXDoctorActivity2 = PXDoctorActivity.f;
                        Intrinsics.d(pXDoctorActivity2);
                        Intrinsics.d(button5);
                        Intrinsics.d(button4);
                        q.G(pXDoctorActivity2, view3, button5, button4, new com.braze.ui.inappmessage.listeners.a(29));
                        break;
                }
            }
        });
        button2.setOnTouchListener(new com.braze.ui.a(14));
        ((Button) viewInflate.findViewById(R.id.doctor_test_selection_web_view_fake_button)).setText("TESTING");
        ((TextView) viewInflate.findViewById(R.id.doctor_test_selection_web_view_text_view)).setText("Web view framework");
        Button button3 = (Button) viewInflate.findViewById(R.id.doctor_test_selection_continue_to_test_result_button);
        button3.setText("Continue to test results");
        button3.setOnClickListener(new com.braze.ui.inappmessage.f(12));
        button3.setOnTouchListener(new com.braze.ui.a(16));
        ImageView imageView = (ImageView) viewInflate.findViewById(R.id.doctor_test_selection_image_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        imageView.setImageBitmap(((C1721Kc) fVar.f).a("noun_refresh_smartphone_small"));
        Button button4 = (Button) viewInflate.findViewById(R.id.doctor_test_selection_native_fake_button);
        Resources resources = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar2);
        button4.setBackground(new BitmapDrawable(resources, ((C1721Kc) fVar2.f).a("native_button_pressed")));
        Button button5 = (Button) viewInflate.findViewById(R.id.doctor_test_selection_native_button);
        Resources resources2 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar3);
        button5.setBackground(new BitmapDrawable(resources2, ((C1721Kc) fVar3.f).a("native_button")));
        Button button6 = (Button) viewInflate.findViewById(R.id.doctor_test_selection_web_view_fake_button);
        Resources resources3 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar4 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar4);
        button6.setBackground(new BitmapDrawable(resources3, ((C1721Kc) fVar4.f).a("webview_button_pressed")));
        Button button7 = (Button) viewInflate.findViewById(R.id.doctor_test_selection_web_view_button);
        Resources resources4 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar5 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar5);
        button7.setBackground(new BitmapDrawable(resources4, ((C1721Kc) fVar5.f).a("webview_button")));
        Button button8 = (Button) viewInflate.findViewById(R.id.doctor_test_selection_continue_to_test_result_button);
        Resources resources5 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar6 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar6);
        button8.setBackground(new BitmapDrawable(resources5, ((C1721Kc) fVar6.f).a("rectangle_empty_regular")));
        return viewInflate;
    }
}
