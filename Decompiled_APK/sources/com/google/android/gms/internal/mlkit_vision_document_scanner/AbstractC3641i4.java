package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.Color;
import android.graphics.Typeface;
import android.widget.Button;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.i4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3641i4 {
    public static final /* synthetic */ int a = 0;

    public static final void a(Button button, androidx.constraintlayout.motion.widget.n buttonProperty, String str, String str2, String str3, OTConfiguration oTConfiguration) {
        Intrinsics.checkNotNullParameter(button, "<this>");
        Intrinsics.checkNotNullParameter(buttonProperty, "buttonProperty");
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) buttonProperty.d;
        Intrinsics.checkNotNullExpressionValue(kVar, "buttonProperty.fontProperty");
        b(button, kVar, oTConfiguration);
        String str4 = (String) kVar.d;
        if (str4 != null && str4.length() != 0) {
            String str5 = (String) kVar.d;
            Intrinsics.d(str5);
            button.setTextSize(Float.parseFloat(str5));
        }
        c(button, str2);
        assistantMode.utils.studiableMetadata.b.q(button.getContext(), button, buttonProperty, str, str3);
    }

    public static final void b(Button button, com.google.android.gms.cloudmessaging.k titleFontProperty, OTConfiguration oTConfiguration) {
        Typeface typeface;
        Typeface otTypeFaceMap;
        Intrinsics.checkNotNullParameter(button, "<this>");
        Intrinsics.checkNotNullParameter(titleFontProperty, "titleFontProperty");
        String str = (String) titleFontProperty.e;
        if (str != null && str.length() != 0 && oTConfiguration != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) != null) {
            button.setTypeface(otTypeFaceMap);
            return;
        }
        int style = titleFontProperty.b;
        if (style == -1 && (typeface = button.getTypeface()) != null) {
            style = typeface.getStyle();
        }
        String str2 = (String) titleFontProperty.c;
        button.setTypeface((str2 == null || str2.length() == 0) ? Typeface.create(button.getTypeface(), style) : Typeface.create((String) titleFontProperty.c, style));
    }

    public static final void c(Button button, String str) {
        Intrinsics.checkNotNullParameter(button, "<this>");
        if (str == null || str.length() == 0) {
            return;
        }
        button.setTextColor(Color.parseColor(str));
    }
}
