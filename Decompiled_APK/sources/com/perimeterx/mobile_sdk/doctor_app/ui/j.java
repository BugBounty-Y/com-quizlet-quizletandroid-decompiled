package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.content.res.Resources;
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
public final class j extends Fragment {
    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_px_doctor_product_selection, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        ((TextView) viewInflate.findViewById(R.id.doctor_product_selection_title_label)).setText("Validate your Integration");
        ((TextView) viewInflate.findViewById(R.id.doctor_product_selection_subtitle_label)).setText("Select the PerimeterX product for which you wish to verifying the Mobile SDK integration");
        Button button = (Button) viewInflate.findViewById(R.id.doctor_product_selection_bot_defender_button);
        Resources resources = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        button.setBackground(new BitmapDrawable(resources, ((C1721Kc) fVar.f).a("bot_defender_button_regular")));
        Button button2 = (Button) viewInflate.findViewById(R.id.doctor_product_selection_account_defender_button);
        Resources resources2 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar2);
        button2.setBackground(new BitmapDrawable(resources2, ((C1721Kc) fVar2.f).a("account_defender_button_regular")));
        Button button3 = (Button) viewInflate.findViewById(R.id.doctor_product_selection_bot_defender_button);
        button3.setOnClickListener(new com.braze.ui.inappmessage.f(9));
        button3.setOnTouchListener(new com.braze.ui.a(11));
        Button button4 = (Button) viewInflate.findViewById(R.id.doctor_product_selection_account_defender_button);
        button4.setOnClickListener(new com.braze.ui.inappmessage.f(10));
        button4.setOnTouchListener(new com.braze.ui.a(12));
        return viewInflate;
    }
}
