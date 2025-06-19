package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.app.Dialog;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.text.Html;
import android.text.SpannableStringBuilder;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.onetrust.otpublishers.headless.qrcode.OTQRCodeUtils;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.f4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3617f4 {
    public static final /* synthetic */ int a = 0;

    public static int a(int i, KeyEvent keyEvent) {
        if (keyEvent.getAction() != 0) {
            return 20;
        }
        if (i == 4) {
            return 23;
        }
        if (i == 61) {
            return 22;
        }
        if (i == 66) {
            return 21;
        }
        switch (i) {
        }
        return 20;
    }

    public static GradientDrawable b(boolean z, String str, String str2, String str3, String str4, ImageView imageView) {
        float f;
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(1);
        gradientDrawable.setCornerRadius(Float.parseFloat("3"));
        if (z) {
            gradientDrawable.setStroke(Integer.parseInt("2"), l(str));
            gradientDrawable.setColor(l(str2));
            f = 6.0f;
        } else {
            gradientDrawable.setStroke(Integer.parseInt("2"), l(str3));
            gradientDrawable.setColor(l(str4));
            f = DefinitionKt.NO_Float_VALUE;
        }
        imageView.setElevation(f);
        return gradientDrawable;
    }

    public static String c(String str) {
        if (str.isEmpty()) {
            return "";
        }
        if (!Pattern.compile(".*\\<[^>]+>.*", 32).matcher(str).matches()) {
            return str.replace("[", "").replace("]", "").replace("\"", "").replace("\\", "");
        }
        String strReplace = str.replace("\\/", "/");
        if (strReplace.startsWith("[") || strReplace.endsWith("]")) {
            strReplace = strReplace.replace("[", "").replace("]", "").replace("\"", "").replace("\\", "");
        }
        return new SpannableStringBuilder(Html.fromHtml(strReplace, null, new com.onetrust.otpublishers.headless.UI.Helper.e())).toString();
    }

    public static void d(Button button, androidx.constraintlayout.motion.widget.n nVar) {
        button.setVisibility(nVar.c());
        button.setText(nVar.a());
        m(button, nVar, false);
    }

    public static void e(Button button, androidx.constraintlayout.motion.widget.n nVar, boolean z) {
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(0);
        gradientDrawable.setCornerRadius(Float.parseFloat("3"));
        if (z) {
            gradientDrawable.setStroke(Integer.parseInt("2"), l((String) nVar.n));
            gradientDrawable.setColor(l((String) nVar.l));
            button.setTextColor(l((String) nVar.m));
            button.setElevation(6.0f);
        } else {
            gradientDrawable.setStroke(Integer.parseInt("2"), l((String) nVar.g));
            gradientDrawable.setColor(l((String) nVar.e));
            button.setTextColor(l(nVar.b()));
            button.setElevation(DefinitionKt.NO_Float_VALUE);
        }
        button.setBackground(gradientDrawable);
        button.setMinHeight(5);
        button.setMinimumHeight(5);
    }

    public static void f(TextView textView, String str) {
        for (Drawable drawable : textView.getCompoundDrawables()) {
            if (drawable != null) {
                drawable.setColorFilter(new PorterDuffColorFilter(l(str), PorterDuff.Mode.SRC_IN));
            }
        }
    }

    public static void g(androidx.fragment.app.I i, String str, String str2, androidx.constraintlayout.motion.widget.n nVar) {
        if (i != null) {
            Dialog dialog = new Dialog(i);
            View viewInflate = i.getLayoutInflater().inflate(R.layout.ot_tv_vendor_qrcode, (ViewGroup) null);
            LinearLayout linearLayout = (LinearLayout) viewInflate.findViewById(R.id.vendor_qrcode_tv_layout);
            TextView textView = (TextView) viewInflate.findViewById(R.id.ot_tv_qr_code_vendor_title);
            ImageView imageView = (ImageView) viewInflate.findViewById(R.id.ot_tv_qr_code_vendor);
            textView.setText(str2);
            String str3 = (String) nVar.l;
            String str4 = (String) nVar.m;
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
                linearLayout.setBackgroundColor(l(str3));
            }
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str4)) {
                textView.setTextColor(l(str4));
            }
            OTQRCodeUtils.b(str, i, "#00000000", str4, imageView, true);
            dialog.setContentView(viewInflate);
            dialog.create();
            dialog.setCancelable(true);
            dialog.show();
        }
    }

    public static void h(boolean z, Button button, com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar, String str, boolean z2) {
        String str2;
        String str3;
        String str4;
        com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = cVar.j;
        androidx.constraintlayout.motion.widget.n nVar = eVar.y;
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(0);
        gradientDrawable.setCornerRadius(Float.parseFloat(str));
        if (z) {
            str2 = (String) nVar.n;
            str3 = (String) nVar.l;
            str4 = (String) nVar.m;
            button.setElevation(6.0f);
        } else if (z2) {
            androidx.camera.camera2.internal.c0 c0Var = eVar.B;
            str4 = (String) c0Var.g;
            str3 = (String) c0Var.f;
            button.setElevation(DefinitionKt.NO_Float_VALUE);
            str2 = str4;
        } else {
            String str5 = (String) nVar.g;
            String str6 = (String) nVar.e;
            String str7 = (String) nVar.f;
            button.setElevation(DefinitionKt.NO_Float_VALUE);
            str2 = str5;
            str3 = str6;
            str4 = str7;
        }
        gradientDrawable.setStroke(Integer.parseInt("2"), l(str2));
        gradientDrawable.setColor(l(str3));
        button.setTextColor(l(str4));
        button.setElevation(6.0f);
        button.setBackground(gradientDrawable);
        button.setMinHeight(0);
        button.setMinimumHeight(0);
    }

    public static void i(boolean z, androidx.constraintlayout.motion.widget.n nVar, ImageView imageView) {
        Drawable background;
        String str;
        if (z) {
            imageView.getDrawable().setTint(l((String) nVar.m));
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
                imageView.setBackground(b(true, (String) nVar.n, (String) nVar.l, (String) nVar.g, (String) nVar.e, imageView));
                return;
            } else {
                background = imageView.getBackground();
                str = (String) nVar.l;
            }
        } else {
            imageView.getDrawable().setTint(l((String) nVar.f));
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
                imageView.setBackground(b(false, (String) nVar.n, (String) nVar.l, (String) nVar.g, (String) nVar.e, imageView));
                return;
            } else {
                background = imageView.getBackground();
                str = (String) nVar.e;
            }
        }
        background.setTint(l(str));
    }

    public static String j(String str) {
        try {
        } catch (Exception e) {
            com.google.android.gms.measurement.internal.Z.n("error on computing dark colors ", e, "TV Utils", 6);
        }
        String str2 = (((double) Integer.valueOf(str.substring(5, 7), 16).intValue()) * 0.114d) + ((((double) Integer.valueOf(str.substring(3, 5), 16).intValue()) * 0.587d) + (((double) Integer.valueOf(str.substring(1, 3), 16).intValue()) * 0.299d)) <= 90.0d ? "bb" : "F1";
        return str.substring(0, 1) + str2 + str.substring(1, str.length());
    }

    public static void k(Button button, androidx.constraintlayout.motion.widget.n nVar, boolean z) {
        if (z) {
            button.setElevation(6.0f);
            if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.l) && !com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.m)) {
                button.getBackground().setTint(l((String) nVar.l));
                button.setTextColor(l((String) nVar.m));
            }
        } else {
            button.setElevation(DefinitionKt.NO_Float_VALUE);
            button.getBackground().setTint(l((String) nVar.e));
            button.setTextColor(l(nVar.b()));
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
            return;
        }
        e(button, nVar, z);
    }

    public static int l(String str) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return 0;
        }
        return Color.parseColor(str);
    }

    public static void m(Button button, androidx.constraintlayout.motion.widget.n nVar, boolean z) {
        button.setElevation(DefinitionKt.NO_Float_VALUE);
        if (nVar.b() != null) {
            button.setTextColor(l(nVar.b()));
        }
        button.getBackground().setTint(l((String) nVar.e));
        if (com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
            return;
        }
        e(button, nVar, z);
    }
}
