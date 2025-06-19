package com.braze.ui;

import android.graphics.Bitmap;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B4;
import com.google.android.material.search.SearchView;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements View.OnTouchListener {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // android.view.View.OnTouchListener
    public final boolean onTouch(View imageView, MotionEvent event) {
        Bitmap bitmapA;
        Bitmap bitmapA2;
        Bitmap bitmap = null;
        switch (this.a) {
            case 0:
                break;
            case 1:
                if (!imageView.hasFocus()) {
                    imageView.requestFocus();
                    break;
                }
                break;
            case 2:
                int i = SearchView.D;
                break;
            case 3:
                u uVar = PXDoctorActivity.e;
                Intrinsics.checkNotNullParameter(imageView, "imageView");
                Intrinsics.checkNotNullParameter(event, "event");
                ImageView imageView2 = (ImageView) imageView;
                androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar);
                Bitmap bitmapA3 = ((C1721Kc) fVar.f).a("close_button_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar2);
                Bitmap bitmapA4 = ((C1721Kc) fVar2.f).a("close_button_pressed");
                Intrinsics.checkNotNullParameter(imageView2, "imageView");
                Intrinsics.checkNotNullParameter(event, "event");
                int action = event.getAction();
                if (action == 0) {
                    bitmap = bitmapA4;
                } else if (action == 1) {
                    bitmap = bitmapA3;
                }
                if (bitmap != null) {
                    imageView2.setImageBitmap(bitmap);
                    break;
                }
                break;
            case 4:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity);
                Integer numValueOf = Integer.valueOf(R.color.DOCTOR_BUTTON_COLOR);
                Integer numValueOf2 = Integer.valueOf(R.color.DOCTOR_BUTTON_TITLE_PRESSED_COLOR);
                androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar3);
                Bitmap bitmapA5 = ((C1721Kc) fVar3.f).a("rectangle_empty_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar4 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar4);
                B4.a((Button) imageView, event, pXDoctorActivity, numValueOf, numValueOf2, bitmapA5, ((C1721Kc) fVar4.f).a("rectangle_empty_pressed"));
                break;
            case 5:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity2 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity2);
                androidx.constraintlayout.core.widgets.analyzer.f fVar5 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar5);
                Bitmap bitmapA6 = ((C1721Kc) fVar5.f).a("rectangle_full_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar6 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar6);
                B4.a((Button) imageView, event, pXDoctorActivity2, null, null, bitmapA6, ((C1721Kc) fVar6.f).a("rectangle_full_pressed"));
                break;
            case 6:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                Button button = (Button) imageView;
                PXDoctorActivity pXDoctorActivity3 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity3);
                androidx.constraintlayout.core.widgets.analyzer.f fVar7 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar7);
                if (((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar7.h).g) {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar8 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    Intrinsics.d(fVar8);
                    bitmapA = ((C1721Kc) fVar8.f).a("rectangle_full_regular");
                } else {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar9 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    Intrinsics.d(fVar9);
                    bitmapA = ((C1721Kc) fVar9.f).a("export_button_regular");
                }
                Bitmap bitmap2 = bitmapA;
                androidx.constraintlayout.core.widgets.analyzer.f fVar10 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar10);
                if (((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar10.h).g) {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar11 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    Intrinsics.d(fVar11);
                    bitmapA2 = ((C1721Kc) fVar11.f).a("rectangle_full_pressed");
                } else {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar12 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    Intrinsics.d(fVar12);
                    bitmapA2 = ((C1721Kc) fVar12.f).a("export_button_pressed");
                }
                B4.a(button, event, pXDoctorActivity3, null, null, bitmap2, bitmapA2);
                break;
            case 7:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity4 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity4);
                Integer numValueOf3 = Integer.valueOf(R.color.DOCTOR_BUTTON_COLOR);
                Integer numValueOf4 = Integer.valueOf(R.color.DOCTOR_BUTTON_TITLE_PRESSED_COLOR);
                androidx.constraintlayout.core.widgets.analyzer.f fVar13 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar13);
                Bitmap bitmapA7 = ((C1721Kc) fVar13.f).a("rectangle_empty_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar14 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar14);
                B4.a((Button) imageView, event, pXDoctorActivity4, numValueOf3, numValueOf4, bitmapA7, ((C1721Kc) fVar14.f).a("rectangle_empty_pressed"));
                break;
            case 8:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity5 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity5);
                B4.a((Button) imageView, event, pXDoctorActivity5, Integer.valueOf(R.color.DOCTOR_LINK_COLOR), Integer.valueOf(R.color.DOCTOR_LINK_PRESSED_COLOR), null, null);
                break;
            case 9:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity6 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity6);
                B4.a((Button) imageView, event, pXDoctorActivity6, Integer.valueOf(R.color.DOCTOR_LINK_COLOR), Integer.valueOf(R.color.DOCTOR_LINK_PRESSED_COLOR), null, null);
                break;
            case 10:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity7 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity7);
                androidx.constraintlayout.core.widgets.analyzer.f fVar15 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar15);
                Bitmap bitmapA8 = ((C1721Kc) fVar15.f).a("rectangle_full_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar16 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar16);
                B4.a((Button) imageView, event, pXDoctorActivity7, null, null, bitmapA8, ((C1721Kc) fVar16.f).a("rectangle_full_pressed"));
                break;
            case 11:
                Intrinsics.checkNotNullParameter(imageView, "button");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity8 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity8);
                androidx.constraintlayout.core.widgets.analyzer.f fVar17 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar17);
                Bitmap bitmapA9 = ((C1721Kc) fVar17.f).a("bot_defender_button_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar18 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar18);
                B4.a((Button) imageView, event, pXDoctorActivity8, null, null, bitmapA9, ((C1721Kc) fVar18.f).a("bot_defender_button_pressed"));
                break;
            case 12:
                Intrinsics.checkNotNullParameter(imageView, "button");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity9 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity9);
                androidx.constraintlayout.core.widgets.analyzer.f fVar19 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar19);
                Bitmap bitmapA10 = ((C1721Kc) fVar19.f).a("account_defender_button_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar20 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar20);
                B4.a((Button) imageView, event, pXDoctorActivity9, null, null, bitmapA10, ((C1721Kc) fVar20.f).a("account_defender_button_pressed"));
                break;
            case 13:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                ImageView imageView3 = (ImageView) imageView;
                androidx.constraintlayout.core.widgets.analyzer.f fVar21 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar21);
                Bitmap bitmapA11 = ((C1721Kc) fVar21.f).a("share");
                androidx.constraintlayout.core.widgets.analyzer.f fVar22 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar22);
                Bitmap bitmapA12 = ((C1721Kc) fVar22.f).a("share_pressed");
                Intrinsics.checkNotNullParameter(imageView3, "imageView");
                Intrinsics.checkNotNullParameter(event, "event");
                int action2 = event.getAction();
                if (action2 == 0) {
                    bitmap = bitmapA12;
                } else if (action2 == 1) {
                    bitmap = bitmapA11;
                }
                if (bitmap != null) {
                    imageView3.setImageBitmap(bitmap);
                    break;
                }
                break;
            case 14:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity10 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity10);
                Integer numValueOf5 = Integer.valueOf(R.color.DOCTOR_BUTTON_COLOR);
                Integer numValueOf6 = Integer.valueOf(R.color.DOCTOR_BUTTON_PRESSED_COLOR);
                androidx.constraintlayout.core.widgets.analyzer.f fVar23 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar23);
                Bitmap bitmapA13 = ((C1721Kc) fVar23.f).a("webview_button");
                androidx.constraintlayout.core.widgets.analyzer.f fVar24 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar24);
                B4.a((Button) imageView, event, pXDoctorActivity10, numValueOf5, numValueOf6, bitmapA13, ((C1721Kc) fVar24.f).a("webview_button_pressed"));
                break;
            case 15:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity11 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity11);
                Integer numValueOf7 = Integer.valueOf(R.color.DOCTOR_BUTTON_COLOR);
                Integer numValueOf8 = Integer.valueOf(R.color.DOCTOR_BUTTON_PRESSED_COLOR);
                androidx.constraintlayout.core.widgets.analyzer.f fVar25 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar25);
                Bitmap bitmapA14 = ((C1721Kc) fVar25.f).a("native_button");
                androidx.constraintlayout.core.widgets.analyzer.f fVar26 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar26);
                B4.a((Button) imageView, event, pXDoctorActivity11, numValueOf7, numValueOf8, bitmapA14, ((C1721Kc) fVar26.f).a("native_button_pressed"));
                break;
            case 16:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity12 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity12);
                Integer numValueOf9 = Integer.valueOf(R.color.DOCTOR_BUTTON_COLOR);
                Integer numValueOf10 = Integer.valueOf(R.color.DOCTOR_BUTTON_TITLE_PRESSED_COLOR);
                androidx.constraintlayout.core.widgets.analyzer.f fVar27 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar27);
                Bitmap bitmapA15 = ((C1721Kc) fVar27.f).a("rectangle_empty_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar28 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar28);
                B4.a((Button) imageView, event, pXDoctorActivity12, numValueOf9, numValueOf10, bitmapA15, ((C1721Kc) fVar28.f).a("rectangle_empty_pressed"));
                break;
            case 17:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity13 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity13);
                androidx.constraintlayout.core.widgets.analyzer.f fVar29 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar29);
                Bitmap bitmapA16 = ((C1721Kc) fVar29.f).a("rectangle_full_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar30 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar30);
                B4.a((Button) imageView, event, pXDoctorActivity13, null, null, bitmapA16, ((C1721Kc) fVar30.f).a("rectangle_full_pressed"));
                break;
            case 18:
                Intrinsics.checkNotNullParameter(imageView, "view");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity14 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity14);
                Integer numValueOf11 = Integer.valueOf(R.color.DOCTOR_BUTTON_COLOR);
                Integer numValueOf12 = Integer.valueOf(R.color.DOCTOR_BUTTON_TITLE_PRESSED_COLOR);
                androidx.constraintlayout.core.widgets.analyzer.f fVar31 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar31);
                Bitmap bitmapA17 = ((C1721Kc) fVar31.f).a("rectangle_empty_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar32 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar32);
                B4.a((Button) imageView, event, pXDoctorActivity14, numValueOf11, numValueOf12, bitmapA17, ((C1721Kc) fVar32.f).a("rectangle_empty_pressed"));
                break;
            case 19:
                Intrinsics.checkNotNullParameter(imageView, "button");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity15 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity15);
                Integer numValueOf13 = Integer.valueOf(R.color.DOCTOR_BUTTON_COLOR);
                Integer numValueOf14 = Integer.valueOf(R.color.DOCTOR_BUTTON_TITLE_PRESSED_COLOR);
                androidx.constraintlayout.core.widgets.analyzer.f fVar33 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar33);
                Bitmap bitmapA18 = ((C1721Kc) fVar33.f).a("rectangle_empty_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar34 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar34);
                B4.a((Button) imageView, event, pXDoctorActivity15, numValueOf13, numValueOf14, bitmapA18, ((C1721Kc) fVar34.f).a("rectangle_empty_pressed"));
                break;
            default:
                Intrinsics.checkNotNullParameter(imageView, "button");
                Intrinsics.checkNotNullParameter(event, "event");
                PXDoctorActivity pXDoctorActivity16 = PXDoctorActivity.f;
                Intrinsics.d(pXDoctorActivity16);
                androidx.constraintlayout.core.widgets.analyzer.f fVar35 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar35);
                Bitmap bitmapA19 = ((C1721Kc) fVar35.f).a("rectangle_full_regular");
                androidx.constraintlayout.core.widgets.analyzer.f fVar36 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar36);
                B4.a((Button) imageView, event, pXDoctorActivity16, null, null, bitmapA19, ((C1721Kc) fVar36.f).a("rectangle_full_pressed"));
                break;
        }
        return false;
    }
}
