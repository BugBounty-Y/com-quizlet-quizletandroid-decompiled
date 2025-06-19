package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.transition.TransitionManager;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.LinearInterpolator;
import android.view.animation.RotateAnimation;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C4;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k extends ArrayAdapter {
    public final ListView a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(PXDoctorActivity context, ArrayList dataSource, ListView listView) {
        super(context, 0, dataSource);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(listView, "listView");
        this.a = listView;
    }

    public static void a(View view, int i, boolean z, boolean z2, boolean z3) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        float f;
        Intrinsics.checkNotNullParameter(view, "view");
        TextView textView = (TextView) view.findViewById(R.id.summary_item_description_text_view);
        TextView textView2 = (TextView) view.findViewById(R.id.summary_item_troubleshooting_title_text_view);
        TextView textView3 = (TextView) view.findViewById(R.id.summary_item_troubleshooting_value_text_view);
        ImageView imageView = (ImageView) view.findViewById(R.id.summary_item_arrow_image_view);
        ((TextView) view.findViewById(R.id.summary_item_troubleshooting_title_text_view)).setText("Troubleshooting");
        if (z) {
            HashSet hashSet = m.a;
            if (hashSet.contains(Integer.valueOf(i))) {
                hashSet.remove(Integer.valueOf(i));
            } else {
                hashSet.add(Integer.valueOf(i));
            }
        }
        HashSet hashSet2 = m.a;
        if (hashSet2.contains(Integer.valueOf(i))) {
            textView.setVisibility(0);
            textView2.setVisibility(z2 ? 0 : 8);
            textView3.setVisibility(z2 ? 0 : 8);
            f = 180.0f;
        } else {
            textView.setVisibility(8);
            textView2.setVisibility(8);
            textView3.setVisibility(8);
            f = 0.0f;
        }
        RotateAnimation rotateAnimation = new RotateAnimation(180.0f - f, f, 1, 0.5f, 1, 0.5f);
        rotateAnimation.setDuration(z3 ? 330L : 0L);
        rotateAnimation.setFillAfter(true);
        rotateAnimation.setInterpolator(new LinearInterpolator());
        imageView.startAnimation(rotateAnimation);
        View viewFindViewById = view.findViewById(R.id.constraintLayout);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        ConstraintLayout constraintLayout = (ConstraintLayout) viewFindViewById;
        androidx.constraintlayout.widget.o oVar = new androidx.constraintlayout.widget.o();
        oVar.d(constraintLayout);
        oVar.c(R.id.summary_item_title_text_view);
        oVar.c(R.id.summary_item_description_text_view);
        if (hashSet2.contains(Integer.valueOf(i))) {
            oVar.e(R.id.summary_item_title_text_view, 4, R.id.summary_item_description_text_view, 3, 40);
            oVar.e(R.id.summary_item_title_text_view, 3, R.id.summary_item_content_view, 3, 77);
            if (z2) {
                oVar.e(R.id.summary_item_description_text_view, 4, R.id.summary_item_troubleshooting_title_text_view, 4, 100);
                oVar.e(R.id.summary_item_troubleshooting_title_text_view, 4, R.id.summary_item_troubleshooting_value_text_view, 3, 0);
                oVar.e(R.id.summary_item_troubleshooting_value_text_view, 4, R.id.summary_item_content_view, 4, 40);
            } else {
                oVar.e(R.id.summary_item_description_text_view, 4, R.id.summary_item_content_view, 4, 40);
            }
        } else {
            oVar.e(R.id.summary_item_title_text_view, 4, R.id.summary_item_content_view, 4, 70);
        }
        TransitionManager.beginDelayedTransition(constraintLayout);
        oVar.a(constraintLayout);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x002d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(com.perimeterx.mobile_sdk.doctor_app.model.g r11, com.perimeterx.mobile_sdk.doctor_app.model.d r12, android.view.View r13, int r14, int r15) {
        /*
            Method dump skipped, instructions count: 305
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.doctor_app.ui.k.b(com.perimeterx.mobile_sdk.doctor_app.model.g, com.perimeterx.mobile_sdk.doctor_app.model.d, android.view.View, int, int):void");
    }

    @Override // android.widget.ArrayAdapter, android.widget.Adapter
    public final View getView(int i, View view, ViewGroup parent) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Bitmap bitmapA;
        int iOrdinal;
        int iOrdinal2;
        Intrinsics.checkNotNullParameter(parent, "parent");
        Object item = getItem(i);
        Intrinsics.d(item);
        com.perimeterx.mobile_sdk.doctor_app.model.f fVar = (com.perimeterx.mobile_sdk.doctor_app.model.f) item;
        com.perimeterx.mobile_sdk.doctor_app.model.g gVar = com.perimeterx.mobile_sdk.doctor_app.model.g.b;
        com.perimeterx.mobile_sdk.doctor_app.model.g gVar2 = fVar.a;
        View viewInflate = gVar2 == gVar ? LayoutInflater.from(getContext()).inflate(R.layout.view_px_doctor_summary_header, parent, false) : fVar.b() ? LayoutInflater.from(getContext()).inflate(R.layout.view_px_doctor_summary_section, parent, false) : LayoutInflater.from(getContext()).inflate(R.layout.view_px_doctor_summary_item, parent, false);
        if (gVar2 == gVar) {
            Intrinsics.d(viewInflate);
            ((TextView) viewInflate.findViewById(R.id.summary_header_summary_title_text_view)).setText("Integration test results");
            DateFormat dateFormat = android.text.format.DateFormat.getDateFormat(getContext());
            DateFormat timeInstance = DateFormat.getTimeInstance(3);
            StringBuilder sb = new StringBuilder();
            com.perimeterx.mobile_sdk.doctor_app.model.d dVar = fVar.b;
            Date date = dVar.b;
            Intrinsics.d(date);
            sb.append(dateFormat.format(date));
            sb.append(", ");
            Date date2 = dVar.b;
            Intrinsics.d(date2);
            sb.append(timeInstance.format(date2));
            ((TextView) viewInflate.findViewById(R.id.summary_header_date_text_view)).setText(com.perimeterx.mobile_sdk.configurations.i.a("Generated: %@", sb.toString()));
            ImageView imageView = (ImageView) viewInflate.findViewById(R.id.summary_header_share_button);
            Resources resources = getContext().getResources();
            androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar2);
            imageView.setBackground(new BitmapDrawable(resources, ((C1721Kc) fVar2.f).a("share")));
            imageView.setOnClickListener(new com.braze.ui.inappmessage.f(11));
            imageView.setOnTouchListener(new com.braze.ui.a(13));
            b(com.perimeterx.mobile_sdk.doctor_app.model.g.c, fVar.b, viewInflate, R.id.summary_header_go_to_configuration_button, R.id.summary_header_configuration_title_text_view);
            b(com.perimeterx.mobile_sdk.doctor_app.model.g.f, fVar.b, viewInflate, R.id.summary_header_go_to_native_button, R.id.summary_header_native_title_text_view);
            b(com.perimeterx.mobile_sdk.doctor_app.model.g.q, fVar.b, viewInflate, R.id.summary_header_go_to_web_view_button, R.id.summary_header_web_view_title_text_view);
            ((TextView) viewInflate.findViewById(R.id.summary_header_table_title_text_view)).setText("Details");
            ImageView imageView2 = (ImageView) viewInflate.findViewById(R.id.summary_header_table_background_top_left_image_view);
            androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar3);
            imageView2.setImageBitmap(((C1721Kc) fVar3.f).a("table_background_top_left"));
            ImageView imageView3 = (ImageView) viewInflate.findViewById(R.id.summary_header_table_background_bottom_image_view);
            androidx.constraintlayout.core.widgets.analyzer.f fVar4 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar4);
            imageView3.setImageBitmap(((C1721Kc) fVar4.f).a("table_background_bottom"));
            ImageView imageView4 = (ImageView) viewInflate.findViewById(R.id.summary_header_table_background_top_right_image_view);
            androidx.constraintlayout.core.widgets.analyzer.f fVar5 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar5);
            imageView4.setImageBitmap(((C1721Kc) fVar5.f).a("table_background_top_right"));
            ImageView imageView5 = (ImageView) viewInflate.findViewById(R.id.summary_header_table_background_top_center_image_view);
            androidx.constraintlayout.core.widgets.analyzer.f fVar6 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar6);
            imageView5.setImageBitmap(((C1721Kc) fVar6.f).a("table_background_top_center"));
            return viewInflate;
        }
        if (fVar.b()) {
            Intrinsics.d(viewInflate);
            ((TextView) viewInflate.findViewById(R.id.summary_section_title_text_view)).setText(gVar2.b());
            ImageView imageView6 = (ImageView) viewInflate.findViewById(R.id.summary_section_table_background_bottom_image_view);
            androidx.constraintlayout.core.widgets.analyzer.f fVar7 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar7);
            imageView6.setImageBitmap(((C1721Kc) fVar7.f).a("table_background_bottom"));
            return viewInflate;
        }
        Intrinsics.d(viewInflate);
        boolean z = gVar2 == com.perimeterx.mobile_sdk.doctor_app.model.g.d || gVar2 == com.perimeterx.mobile_sdk.doctor_app.model.g.e;
        ((TextView) viewInflate.findViewById(R.id.summary_item_title_text_view)).setText(gVar2.b());
        int i2 = 8;
        viewInflate.findViewById(R.id.summary_item_top_line_view).setVisibility((z || (iOrdinal2 = gVar2.ordinal()) == 2 || iOrdinal2 == 5 || iOrdinal2 == 11 || iOrdinal2 == 16 || iOrdinal2 == 19) ? 8 : 0);
        View viewFindViewById = viewInflate.findViewById(R.id.summary_item_bottom_line_view);
        if (!z && (iOrdinal = gVar2.ordinal()) != 3 && iOrdinal != 10 && iOrdinal != 14 && iOrdinal != 18 && iOrdinal != 19) {
            i2 = 0;
        }
        viewFindViewById.setVisibility(i2);
        com.perimeterx.mobile_sdk.doctor_app.model.h hVarE = fVar.e();
        if (hVarE != null) {
            ImageView imageView7 = (ImageView) viewInflate.findViewById(R.id.summary_item_mark_image_view);
            Intrinsics.d(imageView7);
            int iOrdinal3 = hVarE.ordinal();
            if (iOrdinal3 == 0) {
                androidx.constraintlayout.core.widgets.analyzer.f fVar8 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar8);
                bitmapA = ((C1721Kc) fVar8.f).a("success_small");
            } else if (iOrdinal3 == 1) {
                androidx.constraintlayout.core.widgets.analyzer.f fVar9 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar9);
                bitmapA = ((C1721Kc) fVar9.f).a("failure_small");
            } else {
                if (iOrdinal3 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                androidx.constraintlayout.core.widgets.analyzer.f fVar10 = androidx.constraintlayout.core.widgets.analyzer.f.j;
                Intrinsics.d(fVar10);
                bitmapA = ((C1721Kc) fVar10.f).a("skipped_small");
            }
            imageView7.setImageBitmap(bitmapA);
        }
        ImageView imageView8 = (ImageView) viewInflate.findViewById(R.id.summary_item_arrow_image_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar11 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar11);
        imageView8.setImageBitmap(((C1721Kc) fVar11.f).a("noun_arrow"));
        ImageView imageView9 = (ImageView) viewInflate.findViewById(R.id.summary_item_background_image_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar12 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar12);
        imageView9.setImageBitmap(((C1721Kc) fVar12.f).a("table_background_bottom"));
        TextView textView = (TextView) viewInflate.findViewById(R.id.summary_item_description_text_view);
        String str = "Checks whether a challenge is displayed to the user.";
        switch (gVar2.ordinal()) {
            case 2:
                str = "Checks whether your application calls the SDK’s Start method from the correct location (learn more).";
                break;
            case 3:
                str = "Checks whether your application is using the correct AppID.";
                break;
            case 4:
            case 15:
            default:
                str = null;
                break;
            case 5:
                str = "Checks whether your application is requesting the SDK's HTTP headers (learn more).";
                break;
            case 6:
                str = "Checks whether your application is sending the required response to the SDK (learn more).";
                break;
            case 7:
                str = "Checks whether the challenge being prompted is compatible with mobile apps.";
                break;
            case 8:
            case 17:
                break;
            case 9:
            case 18:
                str = "Checks whether the challenge has been dismissed.";
                break;
            case 10:
                str = "Checks whether your application is handling callbacks from the SDK (learn more).";
                break;
            case 11:
                str = "Check that you are signed in with an user.";
                break;
            case 12:
                str = "Check that a device fingerprint was created to enable the service.";
                break;
            case 13:
                str = "Checks whether your application is sending outgoing URL requests to the SDK (learn more).";
                break;
            case 14:
                str = "Checks whether your application is sending additional data to the SDK (learn more).";
                break;
            case 16:
                str = "Checks whether the prompt challenge is compatible for mobile.";
                break;
            case 19:
                str = "Checks whether the mobile data was set in the web view.";
                break;
        }
        textView.setText(str);
        int i3 = androidx.compose.ui.text.platform.e.c;
        C4.a(textView, "learn more", new com.braze.requests.framework.o(this, 17));
        TextView textView2 = (TextView) viewInflate.findViewById(R.id.summary_item_troubleshooting_value_text_view);
        ArrayList arrayListC = gVar2.c();
        boolean z2 = arrayListC.size() > 0;
        int size = arrayListC.size();
        String str2 = "";
        int i4 = 0;
        while (i4 < size) {
            int i5 = i4 + 1;
            str2 = str2 + i5 + ".\t" + ((String) arrayListC.get(i4));
            if (i4 < arrayListC.size() - 1) {
                str2 = str2 + '\n';
            }
            i4 = i5;
        }
        textView2.setText(str2);
        com.perimeterx.mobile_sdk.doctor_app.model.h hVarE2 = fVar.e();
        a(viewInflate, i, false, z2 && (hVarE2 != null && hVarE2 == com.perimeterx.mobile_sdk.doctor_app.model.h.b), false);
        return viewInflate;
    }
}
