package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.res.Resources;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.google.android.gms.ads.internal.client.C1614q;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.lang.ref.WeakReference;
import java.util.List;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.fg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ViewTreeObserverOnScrollChangedListenerC2057fg extends FrameLayout implements ViewTreeObserver.OnScrollChangedListener, ViewTreeObserver.OnGlobalLayoutListener {
    public final Context a;
    public View b;

    public ViewTreeObserverOnScrollChangedListenerC2057fg(Context context) {
        super(context);
        this.a = context;
    }

    public static ViewTreeObserverOnScrollChangedListenerC2057fg a(Context context, View view, Vp vp) {
        ViewTreeObserver viewTreeObserver;
        ViewTreeObserver viewTreeObserver2;
        Resources resources;
        DisplayMetrics displayMetrics;
        ViewTreeObserverOnScrollChangedListenerC2057fg viewTreeObserverOnScrollChangedListenerC2057fg = new ViewTreeObserverOnScrollChangedListenerC2057fg(context);
        List list = vp.u;
        boolean zIsEmpty = list.isEmpty();
        Context context2 = viewTreeObserverOnScrollChangedListenerC2057fg.a;
        if (!zIsEmpty && (resources = context2.getResources()) != null && (displayMetrics = resources.getDisplayMetrics()) != null) {
            float f = ((Wp) list.get(0)).a;
            float f2 = displayMetrics.density;
            viewTreeObserverOnScrollChangedListenerC2057fg.setLayoutParams(new FrameLayout.LayoutParams((int) (f * f2), (int) (r5.b * f2)));
        }
        viewTreeObserverOnScrollChangedListenerC2057fg.b = view;
        viewTreeObserverOnScrollChangedListenerC2057fg.addView(view);
        L9 l9 = com.google.android.gms.ads.internal.j.C.B;
        ViewTreeObserverOnScrollChangedListenerC2485pd viewTreeObserverOnScrollChangedListenerC2485pd = new ViewTreeObserverOnScrollChangedListenerC2485pd(viewTreeObserverOnScrollChangedListenerC2057fg, viewTreeObserverOnScrollChangedListenerC2057fg);
        View view2 = (View) ((WeakReference) viewTreeObserverOnScrollChangedListenerC2485pd.a).get();
        ViewTreeObserver viewTreeObserver3 = null;
        if (view2 == null || (viewTreeObserver = view2.getViewTreeObserver()) == null || !viewTreeObserver.isAlive()) {
            viewTreeObserver = null;
        }
        if (viewTreeObserver != null) {
            viewTreeObserverOnScrollChangedListenerC2485pd.k1(viewTreeObserver);
        }
        ViewTreeObserverOnGlobalLayoutListenerC2442od viewTreeObserverOnGlobalLayoutListenerC2442od = new ViewTreeObserverOnGlobalLayoutListenerC2442od(viewTreeObserverOnScrollChangedListenerC2057fg, viewTreeObserverOnScrollChangedListenerC2057fg);
        View view3 = (View) ((WeakReference) viewTreeObserverOnGlobalLayoutListenerC2442od.a).get();
        if (view3 != null && (viewTreeObserver2 = view3.getViewTreeObserver()) != null && viewTreeObserver2.isAlive()) {
            viewTreeObserver3 = viewTreeObserver2;
        }
        if (viewTreeObserver3 != null) {
            viewTreeObserverOnGlobalLayoutListenerC2442od.k1(viewTreeObserver3);
        }
        RelativeLayout relativeLayout = new RelativeLayout(context2);
        JSONObject jSONObject = vp.h0;
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("header");
        if (jSONObjectOptJSONObject != null) {
            viewTreeObserverOnScrollChangedListenerC2057fg.b(jSONObjectOptJSONObject, relativeLayout, 10);
        }
        JSONObject jSONObjectOptJSONObject2 = jSONObject.optJSONObject("footer");
        if (jSONObjectOptJSONObject2 != null) {
            viewTreeObserverOnScrollChangedListenerC2057fg.b(jSONObjectOptJSONObject2, relativeLayout, 12);
        }
        viewTreeObserverOnScrollChangedListenerC2057fg.addView(relativeLayout);
        return viewTreeObserverOnScrollChangedListenerC2057fg;
    }

    public final void b(JSONObject jSONObject, RelativeLayout relativeLayout, int i) {
        Context context = this.a;
        TextView textView = new TextView(context);
        textView.setTextColor(-1);
        textView.setBackgroundColor(-16777216);
        textView.setGravity(17);
        textView.setText(jSONObject.optString("text", ""));
        textView.setTextSize((float) jSONObject.optDouble("text_size", 11.0d));
        double dOptDouble = jSONObject.optDouble("padding", 0.0d);
        C1614q c1614q = C1614q.f;
        com.google.android.gms.ads.internal.util.client.c cVar = c1614q.a;
        int iN = com.google.android.gms.ads.internal.util.client.c.n(context, (int) dOptDouble);
        textView.setPadding(0, iN, 0, iN);
        double dOptDouble2 = jSONObject.optDouble(OTUXParamsKeys.OT_UX_HEIGHT, 15.0d);
        com.google.android.gms.ads.internal.util.client.c cVar2 = c1614q.a;
        RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-1, com.google.android.gms.ads.internal.util.client.c.n(context, (int) dOptDouble2));
        layoutParams.addRule(i);
        relativeLayout.addView(textView, layoutParams);
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        getLocationInWindow(new int[2]);
        this.b.setY(-r0[1]);
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public final void onScrollChanged() {
        getLocationInWindow(new int[2]);
        this.b.setY(-r0[1]);
    }
}
