package com.facebook.appevents.suggestedevents;

import android.text.TextUtils;
import android.view.View;
import android.widget.AdapterView;
import android.widget.DatePicker;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.RatingBar;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TimePicker;
import com.facebook.appevents.codeless.internal.g;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();
    public static final List b = B.j(Switch.class, Spinner.class, DatePicker.class, TimePicker.class, RadioGroup.class, RatingBar.class, EditText.class, AdapterView.class);

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0033, code lost:
    
        if (r5.isClickable() == false) goto L16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0035, code lost:
    
        r1.add(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0038, code lost:
    
        r5 = com.facebook.appevents.codeless.internal.g.a(r5).iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0044, code lost:
    
        if (r5.hasNext() == false) goto L29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0046, code lost:
    
        r1.addAll(a((android.view.View) r5.next()));
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.util.ArrayList a(android.view.View r5) {
        /*
            java.lang.Class<com.facebook.appevents.suggestedevents.c> r0 = com.facebook.appevents.suggestedevents.c.class
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r0)
            r2 = 0
            if (r1 == 0) goto La
            return r2
        La:
            java.lang.String r1 = "view"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r1)     // Catch: java.lang.Throwable -> L2d
            java.util.ArrayList r1 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L2d
            r1.<init>()     // Catch: java.lang.Throwable -> L2d
            java.util.List r3 = com.facebook.appevents.suggestedevents.c.b     // Catch: java.lang.Throwable -> L2d
            java.util.Iterator r3 = r3.iterator()     // Catch: java.lang.Throwable -> L2d
        L1a:
            boolean r4 = r3.hasNext()     // Catch: java.lang.Throwable -> L2d
            if (r4 == 0) goto L2f
            java.lang.Object r4 = r3.next()     // Catch: java.lang.Throwable -> L2d
            java.lang.Class r4 = (java.lang.Class) r4     // Catch: java.lang.Throwable -> L2d
            boolean r4 = r4.isInstance(r5)     // Catch: java.lang.Throwable -> L2d
            if (r4 == 0) goto L1a
            goto L54
        L2d:
            r5 = move-exception
            goto L55
        L2f:
            boolean r3 = r5.isClickable()     // Catch: java.lang.Throwable -> L2d
            if (r3 == 0) goto L38
            r1.add(r5)     // Catch: java.lang.Throwable -> L2d
        L38:
            java.util.ArrayList r5 = com.facebook.appevents.codeless.internal.g.a(r5)     // Catch: java.lang.Throwable -> L2d
            java.util.Iterator r5 = r5.iterator()     // Catch: java.lang.Throwable -> L2d
        L40:
            boolean r3 = r5.hasNext()     // Catch: java.lang.Throwable -> L2d
            if (r3 == 0) goto L54
            java.lang.Object r3 = r5.next()     // Catch: java.lang.Throwable -> L2d
            android.view.View r3 = (android.view.View) r3     // Catch: java.lang.Throwable -> L2d
            java.util.ArrayList r3 = a(r3)     // Catch: java.lang.Throwable -> L2d
            r1.addAll(r3)     // Catch: java.lang.Throwable -> L2d
            goto L40
        L54:
            return r1
        L55:
            com.facebook.internal.instrument.crashshield.a.a(r0, r5)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.suggestedevents.c.a(android.view.View):java.util.ArrayList");
    }

    public static final JSONObject b(View view, View clickedView) {
        if (com.facebook.internal.instrument.crashshield.a.b(c.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            Intrinsics.checkNotNullParameter(clickedView, "clickedView");
            JSONObject jSONObject = new JSONObject();
            if (view == clickedView) {
                try {
                    jSONObject.put("is_interacted", true);
                } catch (JSONException unused) {
                }
            }
            e(view, jSONObject);
            JSONArray jSONArray = new JSONArray();
            Iterator it2 = g.a(view).iterator();
            while (it2.hasNext()) {
                jSONArray.put(b((View) it2.next(), clickedView));
            }
            jSONObject.put("childviews", jSONArray);
            return jSONObject;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(c.class, th);
            return null;
        }
    }

    public static final String d(View hostView) {
        if (com.facebook.internal.instrument.crashshield.a.b(c.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(hostView, "hostView");
            String strI = g.i(hostView);
            if (strI.length() > 0) {
                return strI;
            }
            String strJoin = TextUtils.join(" ", a.c(hostView));
            Intrinsics.checkNotNullExpressionValue(strJoin, "join(\" \", childrenText)");
            return strJoin;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(c.class, th);
            return null;
        }
    }

    public static final void e(View view, JSONObject json) {
        if (com.facebook.internal.instrument.crashshield.a.b(c.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            Intrinsics.checkNotNullParameter(json, "json");
            try {
                String strI = g.i(view);
                String strG = g.g(view);
                json.put("classname", view.getClass().getSimpleName());
                json.put("classtypebitmask", g.b(view));
                if (strI.length() > 0) {
                    json.put("text", strI);
                }
                if (strG.length() > 0) {
                    json.put("hint", strG);
                }
                if (view instanceof EditText) {
                    json.put("inputtype", ((EditText) view).getInputType());
                }
            } catch (JSONException unused) {
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(c.class, th);
        }
    }

    public final ArrayList c(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            ArrayList arrayList = new ArrayList();
            Iterator it2 = g.a(view).iterator();
            while (it2.hasNext()) {
                View view2 = (View) it2.next();
                String strI = g.i(view2);
                if (strI.length() > 0) {
                    arrayList.add(strI);
                }
                arrayList.addAll(c(view2));
            }
            return arrayList;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }
}
