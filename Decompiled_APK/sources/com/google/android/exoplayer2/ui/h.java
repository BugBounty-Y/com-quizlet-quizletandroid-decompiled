package com.google.android.exoplayer2.ui;

import android.content.Context;
import android.util.Base64;
import android.widget.FrameLayout;
import com.facebook.internal.Q;
import com.google.android.gms.internal.mlkit_vision_common.S2;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class h extends FrameLayout implements f {
    public final b a;
    public final Q b;
    public List c;
    public c d;
    public float e;

    public h(Context context) {
        super(context, null);
        this.c = Collections.EMPTY_LIST;
        this.d = c.e;
        this.e = 0.0533f;
        b bVar = new b(context, 0);
        this.a = bVar;
        Q q = new Q(context, null);
        this.b = q;
        q.setBackgroundColor(0);
        addView(bVar);
        addView(q);
    }

    @Override // com.google.android.exoplayer2.ui.f
    public final void a(List list, c cVar, float f, float f2) {
        this.d = cVar;
        this.e = f;
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        if (list.size() > 0) {
            list.get(0).getClass();
            throw new ClassCastException();
        }
        if (!this.c.isEmpty() || !arrayList2.isEmpty()) {
            this.c = arrayList2;
            b();
        }
        this.a.a(arrayList, cVar, f, f2);
        invalidate();
    }

    public final void b() {
        String str;
        StringBuilder sb = new StringBuilder();
        String strB = S2.b(this.d.a);
        float f = this.e;
        getHeight();
        float height = f == -3.4028235E38f ? -3.4028235E38f : f * ((getHeight() - getPaddingTop()) - getPaddingBottom());
        String strConcat = "unset";
        if (height == -3.4028235E38f) {
            str = "unset";
        } else {
            Object[] objArr = {Float.valueOf(height / getContext().getResources().getDisplayMetrics().density)};
            int i = com.google.android.exoplayer2.util.a.a;
            str = String.format(Locale.US, "%.2fpx", objArr);
        }
        Float fValueOf = Float.valueOf(1.2f);
        c cVar = this.d;
        int i2 = cVar.c;
        int i3 = cVar.d;
        if (i2 == 1) {
            Object[] objArr2 = {S2.b(i3)};
            int i4 = com.google.android.exoplayer2.util.a.a;
            strConcat = String.format(Locale.US, "1px 1px 0 %1$s, 1px -1px 0 %1$s, -1px 1px 0 %1$s, -1px -1px 0 %1$s", objArr2);
        } else if (i2 == 2) {
            String strB2 = S2.b(i3);
            int i5 = com.google.android.exoplayer2.util.a.a;
            Locale locale = Locale.US;
            strConcat = "0.1em 0.12em 0.15em ".concat(strB2);
        } else if (i2 == 3) {
            String strB3 = S2.b(i3);
            int i6 = com.google.android.exoplayer2.util.a.a;
            Locale locale2 = Locale.US;
            strConcat = "0.06em 0.08em 0.15em ".concat(strB3);
        } else if (i2 == 4) {
            String strB4 = S2.b(i3);
            int i7 = com.google.android.exoplayer2.util.a.a;
            Locale locale3 = Locale.US;
            strConcat = "-0.05em -0.05em 0.15em ".concat(strB4);
        }
        Object[] objArr3 = {strB, str, fValueOf, strConcat};
        int i8 = com.google.android.exoplayer2.util.a.a;
        sb.append(String.format(Locale.US, "<body><div style='-webkit-user-select:none;position:fixed;top:0;bottom:0;left:0;right:0;color:%s;font-size:%s;line-height:%.2f;text-shadow:%s;'>", objArr3));
        HashMap map = new HashMap();
        StringBuilder sb2 = new StringBuilder("default_bg".length() + "default_bg".length() + 5);
        sb2.append(".default_bg,.default_bg *");
        map.put(sb2.toString(), "background-color:" + S2.b(this.d.b) + ";");
        if (this.c.size() > 0) {
            this.c.get(0).getClass();
            throw new ClassCastException();
        }
        sb.append("</div></body></html>");
        StringBuilder sb3 = new StringBuilder("<html><head><style>");
        for (String str2 : map.keySet()) {
            sb3.append(str2);
            sb3.append("{");
            sb3.append((String) map.get(str2));
            sb3.append("}");
        }
        sb3.append("</style></head>");
        sb.insert(0, sb3.toString());
        this.b.loadData(Base64.encodeToString(sb.toString().getBytes(com.google.common.base.c.a), 1), "text/html", "base64");
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        if (!z || this.c.isEmpty()) {
            return;
        }
        b();
    }
}
