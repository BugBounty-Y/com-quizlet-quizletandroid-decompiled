package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.drawable.GradientDrawable;
import android.view.View;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.z4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3776z4 {
    public static final void a(String text, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(text, "text");
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(1632883375);
        int i2 = i | (c0814p2.f(text) ? 4 : 2) | 48;
        if ((i2 & 19) == 18 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
            nVar2 = nVar;
        } else {
            c0814p = c0814p2;
            nVar2 = androidx.compose.ui.n.b;
            androidx.compose.material3.Q4.b(text, nVar2, ((com.quizlet.themes.b) c0814p2.j(com.quizlet.themes.g.a)).b.e(), 0L, null, 0L, null, 0L, 0, false, 0, 0, null, ((com.quizlet.themes.f) c0814p2.j(com.quizlet.themes.w.b)).g, c0814p, i2 & 126, 0, 65528);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.modals.e(text, nVar2, i, 3);
        }
    }

    public static void b(View layout) {
        Intrinsics.checkNotNullParameter(layout, "layout");
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setCornerRadius(40.0f);
        PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
        Intrinsics.d(pXDoctorActivity);
        gradientDrawable.setColor(pXDoctorActivity.getColor(R.color.DOCTOR_BUTTON_COLOR));
        layout.findViewById(R.id.row_item_circle_view).setBackground(gradientDrawable);
    }
}
