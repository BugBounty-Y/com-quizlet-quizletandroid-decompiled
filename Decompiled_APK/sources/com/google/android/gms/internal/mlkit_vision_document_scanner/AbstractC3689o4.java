package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.Html;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.method.LinkMovementMethod;
import android.text.style.URLSpan;
import android.widget.TextView;
import com.appsflyer.AppsFlyerProperties;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.eventlogger.features.pushnotifications.FirebaseMessagePayload;
import com.quizlet.generated.enums.C4492j0;
import com.quizlet.generated.enums.EnumC4495k0;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.o4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3689o4 {
    public static void a(TextView textView, androidx.navigation.internal.m titleProperty, String str, OTConfiguration oTConfiguration, boolean z, int i) throws NumberFormatException {
        String str2 = null;
        if ((i & 2) != 0) {
            str = null;
        }
        if ((i & 4) != 0) {
            oTConfiguration = null;
        }
        if ((i & 8) != 0) {
            z = true;
        }
        Intrinsics.checkNotNullParameter(textView, "<this>");
        Intrinsics.checkNotNullParameter(titleProperty, "titleProperty");
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) titleProperty.d;
        Intrinsics.checkNotNullExpressionValue(kVar, "titleProperty.fontProperty");
        c(textView, kVar, oTConfiguration);
        g(textView, (String) kVar.d);
        if (z) {
            textView.setText((String) titleProperty.g);
        }
        String str3 = (String) titleProperty.b;
        if (str3 != null && str3.length() != 0) {
            str2 = str3;
        }
        if (str2 != null) {
            str = str2;
        }
        textView.setTextColor(Color.parseColor(str));
        f(textView, (String) titleProperty.f);
    }

    public static final void b(TextView textView, androidx.navigation.internal.m titleProperty, String str, boolean z, OTConfiguration oTConfiguration) {
        Intrinsics.checkNotNullParameter(textView, "<this>");
        Intrinsics.checkNotNullParameter(titleProperty, "titleProperty");
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) titleProperty.d;
        Intrinsics.checkNotNullExpressionValue(kVar, "titleProperty.fontProperty");
        c(textView, kVar, oTConfiguration);
        g(textView, (String) kVar.d);
        f(textView, (String) titleProperty.f);
        if (str != null && str.length() != 0) {
            textView.setTextColor(Color.parseColor(str));
        }
        androidx.core.view.V.p(textView, z);
    }

    public static final void c(TextView textView, com.google.android.gms.cloudmessaging.k titleFontProperty, OTConfiguration oTConfiguration) {
        Typeface otTypeFaceMap;
        Intrinsics.checkNotNullParameter(textView, "<this>");
        Intrinsics.checkNotNullParameter(titleFontProperty, "titleFontProperty");
        String str = (String) titleFontProperty.e;
        if (str != null && str.length() != 0 && oTConfiguration != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) != null) {
            textView.setTypeface(otTypeFaceMap);
            return;
        }
        int iA = com.google.android.gms.cloudmessaging.k.a(textView, titleFontProperty.b);
        String str2 = (String) titleFontProperty.c;
        textView.setTypeface((str2 == null || str2.length() == 0) ? Typeface.create(textView.getTypeface(), iA) : Typeface.create((String) titleFontProperty.c, iA));
    }

    public static final void d(TextView textView, com.quizlet.data.repository.user.e linkProperty, androidx.room.s sVar, com.onetrust.otpublishers.headless.UI.DataModels.a bannerData, OTConfiguration oTConfiguration) {
        Intrinsics.checkNotNullParameter(textView, "<this>");
        Intrinsics.checkNotNullParameter(linkProperty, "linkProperty");
        Intrinsics.checkNotNullParameter(bannerData, "bannerData");
        androidx.navigation.internal.m textProperty = (androidx.navigation.internal.m) linkProperty.b;
        Intrinsics.checkNotNullExpressionValue(textProperty, "linkProperty.linkTextProperty");
        String linkColor = bannerData.l;
        if (linkColor == null) {
            linkColor = "";
        }
        Intrinsics.checkNotNullParameter(textProperty, "textProperty");
        Intrinsics.checkNotNullParameter(linkColor, "linkColor");
        String str = (String) textProperty.b;
        String str2 = null;
        if (str == null || str.length() == 0) {
            str = null;
        }
        if (str == null) {
            String str3 = sVar != null ? sVar.b : null;
            if (str3 != null && str3.length() != 0) {
                str2 = str3;
            }
            if (str2 != null) {
                linkColor = str2;
            }
        } else {
            linkColor = str;
        }
        b(textView, textProperty, linkColor, false, oTConfiguration);
        Intrinsics.checkNotNullParameter(textView, "<this>");
        if (sVar == null || sVar.c) {
            textView.setPaintFlags(textView.getPaintFlags() | 8);
        }
    }

    public static final void e(TextView textView, String str) {
        Intrinsics.checkNotNullParameter(textView, "<this>");
        if (str == null || str.length() == 0) {
            OTLogger.c("UIUtils", 3, "renderHtmlText called with 'null' text content.");
            return;
        }
        if (!Pattern.compile(".*\\<[^>]+>.*", 32).matcher(str).matches()) {
            textView.setText(str);
            return;
        }
        OTLogger.c("UIUtils", 3, "Rendering html content");
        Context context = textView.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(context, "context");
        Spanned spannedFromHtml = Html.fromHtml(str, 0);
        Intrinsics.checkNotNullExpressionValue(spannedFromHtml, "{\n        Html.fromHtml(…M_HTML_MODE_LEGACY)\n    }");
        SpannableStringBuilder strBuilder = new SpannableStringBuilder(spannedFromHtml);
        URLSpan[] urls = (URLSpan[]) strBuilder.getSpans(0, spannedFromHtml.length(), URLSpan.class);
        Intrinsics.checkNotNullExpressionValue(urls, "urls");
        for (URLSpan span : urls) {
            Intrinsics.checkNotNullExpressionValue(span, "span");
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(strBuilder, "strBuilder");
            Intrinsics.checkNotNullParameter(span, "span");
            strBuilder.setSpan(new com.onetrust.otpublishers.headless.UI.Helper.d(context, span, 1), strBuilder.getSpanStart(span), strBuilder.getSpanEnd(span), strBuilder.getSpanFlags(span));
            strBuilder.removeSpan(span);
        }
        textView.setText(strBuilder);
        textView.setMovementMethod(LinkMovementMethod.getInstance());
    }

    public static final void f(TextView textView, String str) throws NumberFormatException {
        Intrinsics.checkNotNullParameter(textView, "<this>");
        if (P.k(textView.getContext())) {
            textView.setTextAlignment(5);
            return;
        }
        if (str == null || str.length() == 0) {
            return;
        }
        int layoutDirection = textView.getContext().getResources().getConfiguration().getLayoutDirection();
        int i = Integer.parseInt(str);
        Intrinsics.checkNotNullParameter(textView, "<this>");
        int i2 = 8388613;
        int i3 = 8388611;
        if (layoutDirection != 1) {
            i3 = 8388613;
            i2 = 8388611;
        }
        if (i == 2) {
            textView.setGravity(3);
            return;
        }
        if (i == 3) {
            textView.setGravity(5);
            return;
        }
        if (i == 4) {
            textView.setGravity(1);
        } else if (i == 5) {
            textView.setGravity(i2);
        } else {
            if (i != 6) {
                return;
            }
            textView.setGravity(i3);
        }
    }

    public static final void g(TextView textView, String str) {
        Intrinsics.checkNotNullParameter(textView, "<this>");
        if (str == null || str.length() == 0) {
            return;
        }
        textView.setTextSize(Float.parseFloat(str));
    }

    public static FirebaseMessagePayload h(String jsonData) throws JSONException {
        Long lValueOf;
        com.quizlet.generated.enums.S1 s1;
        EnumC4495k0 enumC4495k0;
        Intrinsics.checkNotNullParameter(jsonData, "jsonData");
        JSONObject jSONObject = new JSONObject(jsonData);
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("modelIds");
        String string = jSONObject.getString("messageId");
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        long j = jSONObject.getLong("userId");
        com.quizlet.generated.enums.R1 r1 = com.quizlet.generated.enums.S1.Companion;
        int i = jSONObject.getInt(DBUserFields.Names.USER_UPGRADE_TYPE);
        r1.getClass();
        com.quizlet.generated.enums.S1[] s1ArrValues = com.quizlet.generated.enums.S1.values();
        int length = s1ArrValues.length;
        int i2 = 0;
        while (true) {
            lValueOf = null;
            if (i2 >= length) {
                s1 = null;
                break;
            }
            s1 = s1ArrValues[i2];
            if (s1.a() == i) {
                break;
            }
            i2++;
        }
        String string2 = jSONObject.getString(AppsFlyerProperties.CHANNEL);
        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
        C4492j0 c4492j0 = EnumC4495k0.Companion;
        int iOptInt = jSONObject.optInt("destination", -1);
        c4492j0.getClass();
        EnumC4495k0[] enumC4495k0ArrValues = EnumC4495k0.values();
        int length2 = enumC4495k0ArrValues.length;
        int i3 = 0;
        while (true) {
            if (i3 >= length2) {
                enumC4495k0 = null;
                break;
            }
            EnumC4495k0 enumC4495k02 = enumC4495k0ArrValues[i3];
            if (enumC4495k02.a() == iOptInt) {
                enumC4495k0 = enumC4495k02;
                break;
            }
            i3++;
        }
        Long lValueOf2 = (jSONObjectOptJSONObject == null || !jSONObjectOptJSONObject.has("set")) ? null : Long.valueOf(jSONObjectOptJSONObject.getJSONArray("set").getLong(0));
        if (jSONObjectOptJSONObject != null && jSONObjectOptJSONObject.has("folder")) {
            lValueOf = Long.valueOf(jSONObjectOptJSONObject.getJSONArray("folder").getLong(0));
        }
        return new FirebaseMessagePayload(string, j, s1, string2, enumC4495k0, lValueOf2, lValueOf);
    }
}
