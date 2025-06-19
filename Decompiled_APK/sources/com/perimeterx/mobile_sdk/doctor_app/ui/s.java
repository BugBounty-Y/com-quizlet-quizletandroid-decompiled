package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.content.res.Resources;
import android.graphics.drawable.BitmapDrawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.ads.C1721Kc;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class s extends Fragment {
    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_px_doctor_waiting_to_start, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        ImageView imageView = (ImageView) viewInflate.findViewById(R.id.doctor_waiting_to_start_image_view_1);
        Resources resources = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        imageView.setBackground(new BitmapDrawable(resources, ((C1721Kc) fVar.f).a("loading_rectangle_2")));
        ImageView imageView2 = (ImageView) viewInflate.findViewById(R.id.doctor_waiting_to_start_image_view_2);
        Resources resources2 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar2);
        imageView2.setBackground(new BitmapDrawable(resources2, ((C1721Kc) fVar2.f).a("loading_rectangle_3")));
        ImageView imageView3 = (ImageView) viewInflate.findViewById(R.id.doctor_waiting_to_start_image_view_3);
        Resources resources3 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar3 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar3);
        imageView3.setBackground(new BitmapDrawable(resources3, ((C1721Kc) fVar3.f).a("loading_oval")));
        ImageView imageView4 = (ImageView) viewInflate.findViewById(R.id.doctor_waiting_to_start_image_view_4);
        Resources resources4 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar4 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar4);
        imageView4.setBackground(new BitmapDrawable(resources4, ((C1721Kc) fVar4.f).a("loading_oval")));
        ImageView imageView5 = (ImageView) viewInflate.findViewById(R.id.doctor_waiting_to_start_image_view_5);
        Resources resources5 = getResources();
        androidx.constraintlayout.core.widgets.analyzer.f fVar5 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar5);
        imageView5.setBackground(new BitmapDrawable(resources5, ((C1721Kc) fVar5.f).a("loading_rectangle_1")));
        return viewInflate;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        com.perimeterx.mobile_sdk.doctor_app.model.a action = new com.perimeterx.mobile_sdk.doctor_app.model.a(new retrofit2.adapter.rxjava3.d(22));
        Intrinsics.checkNotNullParameter(action, "action");
        fVar.d(B.f(action));
    }
}
