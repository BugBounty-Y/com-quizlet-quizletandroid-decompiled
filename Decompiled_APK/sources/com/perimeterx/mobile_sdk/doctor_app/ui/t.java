package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.ads.C1721Kc;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class t extends Fragment {
    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_px_doctor_welcome, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        ((TextView) viewInflate.findViewById(R.id.doctor_welcome_title_label)).setText("Welcome!");
        ((TextView) viewInflate.findViewById(R.id.doctor_welcome_subtitle_label)).setText("PerimeterX can help verify your Mobile SDK integration by simulating a typical user flow in your application.");
        ((TextView) viewInflate.findViewById(R.id.doctor_welcome_emoji_label)).setText("👋");
        ((Button) viewInflate.findViewById(R.id.doctor_welcome_continue_button)).setText("Continue");
        ((Button) viewInflate.findViewById(R.id.doctor_welcome_last_test_results_button)).setText("Open last test results");
        Button button = (Button) viewInflate.findViewById(R.id.doctor_welcome_continue_button);
        Resources resources = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        button.setBackground(new BitmapDrawable(resources, ((C1721Kc) fVar.f).a("rectangle_full_regular")));
        Button button2 = (Button) viewInflate.findViewById(R.id.doctor_welcome_last_test_results_button);
        Resources resources2 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar2);
        button2.setBackground(new BitmapDrawable(resources2, ((C1721Kc) fVar2.f).a("rectangle_empty_regular")));
        Button button3 = (Button) viewInflate.findViewById(R.id.doctor_welcome_continue_button);
        button3.setOnClickListener(new com.braze.ui.inappmessage.f(16));
        button3.setOnTouchListener(new com.braze.ui.a(20));
        Button button4 = (Button) viewInflate.findViewById(R.id.doctor_welcome_last_test_results_button);
        button4.setOnClickListener(new com.braze.ui.inappmessage.f(15));
        button4.setOnTouchListener(new com.braze.ui.a(19));
        androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar3);
        if (fVar3.o() == null) {
            button4.setVisibility(8);
            return viewInflate;
        }
        button4.setVisibility(0);
        View viewFindViewById = viewInflate.findViewById(R.id.constraintLayout);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "findViewById(...)");
        ConstraintLayout constraintLayout = (ConstraintLayout) viewFindViewById;
        androidx.constraintlayout.widget.o oVar = new androidx.constraintlayout.widget.o();
        oVar.d(constraintLayout);
        oVar.c(button3.getId());
        oVar.e(button3.getId(), 4, button4.getId(), 3, 40);
        oVar.a(constraintLayout);
        return viewInflate;
    }
}
