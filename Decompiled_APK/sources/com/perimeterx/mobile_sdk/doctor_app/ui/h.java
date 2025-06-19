package com.perimeterx.mobile_sdk.doctor_app.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListAdapter;
import android.widget.ListView;
import androidx.appcompat.app.C0049e;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3768y4;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class h extends Fragment {
    public static final ArrayList a = B.f("Select your tested environment", "Use your application to generate a typical user flow and trigger URL requests", "Did you have to solve a challenge/Captcha? Great! You’re all set and ready to go!", "No challenge/Captcha? Shake your device to start the validator app and to let us know that you are not getting a challenge");
    public static final ArrayList b = B.f("Select your tested environment", "Use your application to sign in into an account", "Use your application to generate a typical user flow and trigger URL requests", "No confirmation from the Doctor? Shake your device to start the validator app");

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_px_doctor_instructions, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
        Intrinsics.d(pXDoctorActivity);
        ListView listView = (ListView) viewInflate.findViewById(R.id.doctor_instructions_list_view);
        ArrayList instructions = AbstractC3768y4.b();
        Intrinsics.checkNotNullParameter(instructions, "instructions");
        listView.setAdapter((ListAdapter) new C0049e(pXDoctorActivity, 0, instructions, 1));
        return viewInflate;
    }
}
