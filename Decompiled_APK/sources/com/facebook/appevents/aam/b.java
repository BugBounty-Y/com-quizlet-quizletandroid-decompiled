package com.facebook.appevents.aam;

import android.content.res.Resources;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;
import com.facebook.appevents.codeless.internal.g;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class b {
    public static final b a = new b();

    public static final ArrayList a(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            ArrayList arrayList = new ArrayList();
            ViewGroup viewGroupH = g.h(view);
            if (viewGroupH != null) {
                Iterator it2 = g.a(viewGroupH).iterator();
                while (it2.hasNext()) {
                    View view2 = (View) it2.next();
                    if (view != view2) {
                        arrayList.addAll(a.c(view2));
                    }
                }
            }
            return arrayList;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(b.class, th);
            return null;
        }
    }

    public static final ArrayList b(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            ArrayList arrayList = new ArrayList();
            arrayList.add(g.g(view));
            Object tag = view.getTag();
            if (tag != null) {
                arrayList.add(tag.toString());
            }
            CharSequence contentDescription = view.getContentDescription();
            if (contentDescription != null) {
                arrayList.add(contentDescription.toString());
            }
            try {
                if (view.getId() != -1) {
                    String resourceName = view.getResources().getResourceName(view.getId());
                    Intrinsics.checkNotNullExpressionValue(resourceName, "resourceName");
                    String[] strArr = (String[]) new Regex("/").g(0, resourceName).toArray(new String[0]);
                    if (strArr.length == 2) {
                        arrayList.add(strArr[1]);
                    }
                }
            } catch (Resources.NotFoundException unused) {
            }
            ArrayList arrayList2 = new ArrayList();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                String str = (String) it2.next();
                if (str.length() > 0 && str.length() <= 100) {
                    String lowerCase = str.toLowerCase();
                    Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
                    arrayList2.add(lowerCase);
                }
            }
            return arrayList2;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(b.class, th);
            return null;
        }
    }

    public static final boolean d(ArrayList indicators, ArrayList keys) {
        if (!com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            try {
                Intrinsics.checkNotNullParameter(indicators, "indicators");
                Intrinsics.checkNotNullParameter(keys, "keys");
                Iterator it2 = indicators.iterator();
                while (it2.hasNext()) {
                    String str = (String) it2.next();
                    b bVar = a;
                    if (!com.facebook.internal.instrument.crashshield.a.b(bVar)) {
                        try {
                            Iterator it3 = keys.iterator();
                            while (it3.hasNext()) {
                                if (StringsKt.G(str, (String) it3.next(), false)) {
                                    return true;
                                }
                            }
                        } catch (Throwable th) {
                            com.facebook.internal.instrument.crashshield.a.a(bVar, th);
                        }
                    }
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(b.class, th2);
                return false;
            }
        }
        return false;
    }

    public final ArrayList c(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            ArrayList arrayList = new ArrayList();
            if (view instanceof EditText) {
                return arrayList;
            }
            if (view instanceof TextView) {
                String string = ((TextView) view).getText().toString();
                if (string.length() > 0 && string.length() < 100) {
                    String lowerCase = string.toLowerCase();
                    Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
                    arrayList.add(lowerCase);
                    return arrayList;
                }
            } else {
                Iterator it2 = g.a(view).iterator();
                while (it2.hasNext()) {
                    arrayList.addAll(c((View) it2.next()));
                }
            }
            return arrayList;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }
}
