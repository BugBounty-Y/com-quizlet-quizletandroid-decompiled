package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.ads.C1721Kc;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class f extends Fragment {
    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Bitmap bitmapA;
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_px_doctor_exit, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        TextView textView = (TextView) viewInflate.findViewById(R.id.doctor_exit_title_text_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        textView.setText(((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar.h).g ? "Would you like to start a new test?" : "Would you like to export your integration test results before proceeding?");
        TextView textView2 = (TextView) viewInflate.findViewById(R.id.doctor_exit_emoji_text_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar2);
        textView2.setText(((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar2.h).g ? "🎈" : "💌");
        Button button = (Button) viewInflate.findViewById(R.id.doctor_exit_button_1);
        button.setOnClickListener(new com.braze.ui.inappmessage.f(4));
        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
        Intrinsics.d(pXDoctorActivity);
        Resources resources = pXDoctorActivity.getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar3);
        if (((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar3.h).g) {
            androidx.constraintlayout.core.widgets.analyzer.f fVar4 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar4);
            bitmapA = ((C1721Kc) fVar4.f).a("rectangle_full_regular");
        } else {
            androidx.constraintlayout.core.widgets.analyzer.f fVar5 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar5);
            bitmapA = ((C1721Kc) fVar5.f).a("export_button_regular");
        }
        button.setBackground(new BitmapDrawable(resources, bitmapA));
        button.setOnTouchListener(new com.braze.ui.a(6));
        androidx.constraintlayout.core.widgets.analyzer.f fVar6 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar6);
        button.setText(((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar6.h).g ? "Start a new test" : "Export to JSON");
        Button button2 = (Button) viewInflate.findViewById(R.id.doctor_exit_button_2);
        PXDoctorActivity pXDoctorActivity2 = PXDoctorActivity.f;
        Intrinsics.d(pXDoctorActivity2);
        Resources resources2 = pXDoctorActivity2.getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar7 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar7);
        button2.setBackground(new BitmapDrawable(resources2, ((C1721Kc) fVar7.f).a("rectangle_empty_regular")));
        button2.setOnClickListener(new com.braze.ui.inappmessage.f(5));
        button2.setOnTouchListener(new com.braze.ui.a(7));
        androidx.constraintlayout.core.widgets.analyzer.f fVar8 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar8);
        button2.setText(((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar8.h).g ? "Back" : "Start a new test");
        Button button3 = (Button) viewInflate.findViewById(R.id.doctor_exit_button_3);
        button3.setOnClickListener(new com.braze.ui.inappmessage.f(6));
        button3.setOnTouchListener(new com.braze.ui.a(8));
        button3.setText("Back");
        androidx.constraintlayout.core.widgets.analyzer.f fVar9 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar9);
        button3.setVisibility(((com.perimeterx.mobile_sdk.doctor_app.model.c) fVar9.h).g ? 8 : 0);
        return viewInflate;
    }
}
