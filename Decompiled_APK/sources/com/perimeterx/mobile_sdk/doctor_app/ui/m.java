package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ImageView;
import android.widget.ListAdapter;
import android.widget.ListView;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.ads.C1721Kc;
import com.quizlet.quizletandroid.R;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashSet;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class m extends Fragment {
    public static final HashSet a = new HashSet();

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_px_doctor_summary, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        final ListView listView = (ListView) viewInflate.findViewById(R.id.doctor_summary_list_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar);
        com.perimeterx.mobile_sdk.doctor_app.model.d dVar = (com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i;
        androidx.constraintlayout.core.widgets.analyzer.f fVar2 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar2);
        com.perimeterx.mobile_sdk.doctor_app.f fVar3 = (com.perimeterx.mobile_sdk.doctor_app.f) fVar2.g;
        Intrinsics.d(fVar3);
        final androidx.work.impl.constraints.m mVar = new androidx.work.impl.constraints.m(dVar, fVar3);
        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
        Intrinsics.d(pXDoctorActivity);
        ArrayList arrayList = mVar.a;
        Intrinsics.d(listView);
        listView.setAdapter((ListAdapter) new k(pXDoctorActivity, arrayList, listView));
        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() { // from class: com.perimeterx.mobile_sdk.doctor_app.ui.l
            @Override // android.widget.AdapterView.OnItemClickListener
            public final void onItemClick(AdapterView adapterView, View view, int i, long j) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
                HashSet hashSet = m.a;
                Intrinsics.checkNotNullParameter(adapterView, "adapterView");
                Intrinsics.checkNotNullParameter(view, "view");
                Object obj = mVar.a.get(i);
                Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
                com.perimeterx.mobile_sdk.doctor_app.model.f fVar4 = (com.perimeterx.mobile_sdk.doctor_app.model.f) obj;
                if (fVar4.a == com.perimeterx.mobile_sdk.doctor_app.model.g.b || fVar4.b()) {
                    return;
                }
                boolean z = false;
                boolean z2 = fVar4.a.c().size() > 0;
                boolean z3 = fVar4.e() == com.perimeterx.mobile_sdk.doctor_app.model.h.b;
                ListView listView2 = listView;
                ListAdapter adapter = listView2.getAdapter();
                Intrinsics.e(adapter, "null cannot be cast to non-null type com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorSummaryAdapter");
                if (z2 && z3) {
                    z = true;
                }
                k.a(view, i, true, z, true);
                if (m.a.contains(Integer.valueOf(i))) {
                    listView2.smoothScrollToPosition(i);
                }
            }
        });
        ImageView imageView = (ImageView) viewInflate.findViewById(R.id.doctor_summary_image_view);
        androidx.constraintlayout.core.widgets.analyzer.f fVar4 = androidx.constraintlayout.core.widgets.analyzer.f.j;
        Intrinsics.d(fVar4);
        imageView.setImageBitmap(((C1721Kc) fVar4.f).a("table_background_bottom"));
        return viewInflate;
    }
}
