package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.TextView;
import androidx.appcompat.app.C0049e;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.ads.C1721Kc;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class r extends Fragment {
    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        String str;
        ArrayList instructions;
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_px_doctor_tips, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
        Intrinsics.d(pXDoctorActivity);
        ListView listView = (ListView) viewInflate.findViewById(R.id.doctor_tips_list_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        com.perimeterx.mobile_sdk.doctor_app.g type = fVar.f() ? com.perimeterx.mobile_sdk.doctor_app.g.a : fVar.h() ? com.perimeterx.mobile_sdk.doctor_app.g.b : null;
        if (type != null) {
            androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
            Intrinsics.d(fVar2);
            com.perimeterx.mobile_sdk.doctor_app.f productType = (com.perimeterx.mobile_sdk.doctor_app.f) fVar2.g;
            Intrinsics.d(productType);
            Intrinsics.checkNotNullParameter(type, "type");
            Intrinsics.checkNotNullParameter(productType, "productType");
            int iOrdinal = type.ordinal();
            if (iOrdinal == 0) {
                int iOrdinal2 = productType.ordinal();
                if (iOrdinal2 == 0) {
                    instructions = B.f("Make sure that you retrieve the SDK’s http headers and attach them to your URL requests");
                } else {
                    if (iOrdinal2 != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    instructions = B.f("Make sure you are signed in with your user", "Try to navigate to some pages");
                }
            } else {
                if (iOrdinal != 1) {
                    throw new NoWhenBranchMatchedException();
                }
                int iOrdinal3 = productType.ordinal();
                if (iOrdinal3 == 0) {
                    instructions = B.f("Try to navigate to some pages until the captcha will be shown");
                } else {
                    if (iOrdinal3 != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    instructions = B.f("Try to navigate to some pages");
                }
            }
            Intrinsics.checkNotNullParameter(instructions, "instructions");
            listView.setAdapter((ListAdapter) new C0049e(pXDoctorActivity, 0, instructions, 2));
        }
        TextView textView = (TextView) viewInflate.findViewById(R.id.doctor_tips_title_text_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar3);
        com.perimeterx.mobile_sdk.doctor_app.f fVar4 = (com.perimeterx.mobile_sdk.doctor_app.f) fVar3.g;
        Intrinsics.d(fVar4);
        int iOrdinal4 = fVar4.ordinal();
        if (iOrdinal4 == 0) {
            str = "No Challenge received? 🙁";
        } else {
            if (iOrdinal4 != 1) {
                throw new NoWhenBranchMatchedException();
            }
            str = "Nothing happens? 🙁";
        }
        textView.setText(str);
        ((TextView) viewInflate.findViewById(R.id.doctor_tips_subtitle_text_view)).setText("The tips below may help");
        Button button = (Button) viewInflate.findViewById(R.id.doctor_tips_continue_testing_button);
        button.setText("Continue testing");
        button.setOnClickListener(new com.braze.ui.inappmessage.f(13));
        button.setOnTouchListener(new com.braze.ui.a(17));
        Button button2 = (Button) viewInflate.findViewById(R.id.doctor_tips_done_testing_button);
        button2.setText("I’m done testing");
        button2.setOnClickListener(new com.braze.ui.inappmessage.f(14));
        button2.setOnTouchListener(new com.braze.ui.a(18));
        ImageView imageView = (ImageView) viewInflate.findViewById(R.id.doctor_tips_light_image_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar5 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar5);
        imageView.setImageBitmap(((C1721Kc) fVar5.f).a("noun_light_on"));
        Button button3 = (Button) viewInflate.findViewById(R.id.doctor_tips_continue_testing_button);
        Resources resources = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar6 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar6);
        button3.setBackground(new BitmapDrawable(resources, ((C1721Kc) fVar6.f).a("rectangle_full_regular")));
        Button button4 = (Button) viewInflate.findViewById(R.id.doctor_tips_done_testing_button);
        Resources resources2 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar7 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar7);
        button4.setBackground(new BitmapDrawable(resources2, ((C1721Kc) fVar7.f).a("rectangle_empty_regular")));
        return viewInflate;
    }
}
