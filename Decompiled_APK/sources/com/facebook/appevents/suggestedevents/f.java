package com.facebook.appevents.suggestedevents;

import android.view.View;
import com.facebook.appevents.codeless.internal.g;
import com.facebook.internal.J;
import java.lang.ref.WeakReference;
import java.util.HashSet;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class f implements View.OnClickListener {
    public static final HashSet e = new HashSet();
    public final View.OnClickListener a;
    public final WeakReference b;
    public final WeakReference c;
    public final String d;

    public f(View view, View view2, String str) {
        this.a = g.e(view);
        this.b = new WeakReference(view2);
        this.c = new WeakReference(view);
        String lowerCase = str.toLowerCase();
        Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
        this.d = D.o(lowerCase, "activity", "", false);
    }

    public final void a() {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                View view = (View) this.b.get();
                View view2 = (View) this.c.get();
                if (view != null && view2 != null) {
                    try {
                        String strD = c.d(view2);
                        String strB = b.b(view2, strD);
                        if (strB != null && !a.a(strB, strD)) {
                            JSONObject jSONObject = new JSONObject();
                            jSONObject.put("view", c.b(view, view2));
                            jSONObject.put("screenname", this.d);
                            if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                                try {
                                    try {
                                        J.M(new androidx.camera.camera2.internal.compat.b(jSONObject, strD, this, strB, 8));
                                    } catch (Throwable th) {
                                        th = th;
                                        try {
                                            com.facebook.internal.instrument.crashshield.a.a(this, th);
                                        } catch (Exception unused) {
                                        } catch (Throwable th2) {
                                            th = th2;
                                            com.facebook.internal.instrument.crashshield.a.a(this, th);
                                        }
                                    }
                                } catch (Throwable th3) {
                                    th = th3;
                                }
                            }
                        }
                    } catch (Exception unused2) {
                    }
                }
            } catch (Throwable th4) {
                th = th4;
            }
        }
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            View.OnClickListener onClickListener = this.a;
            if (onClickListener != null) {
                onClickListener.onClick(view);
            }
            a();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
