package com.onetrust.otpublishers.headless.UI.adapter;

import android.content.Context;
import android.graphics.Typeface;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.quizlet.quizletandroid.R;
import org.json.JSONArray;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4048d extends AbstractC1361d0 {
    public final OTConfiguration a;
    public final C3 c;
    public final Context e;
    public final com.onetrust.otpublishers.headless.UI.mobiledatautils.b f;
    public final JSONArray g;
    public final String h;
    public final C3 i;
    public final String b = "";
    public final String d = "";

    public C4048d(Context context, JSONArray jSONArray, String str, C3 c3, OTConfiguration oTConfiguration, C3 c32, com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar) {
        this.e = context;
        this.g = jSONArray;
        this.h = str;
        this.i = c3;
        this.a = oTConfiguration;
        this.c = c32;
        this.f = bVar;
    }

    public final void d(C4047c c4047c) throws NumberFormatException {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        C3 c3 = this.i;
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) c3.g;
        TextView textView = c4047c.a;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d)) {
            textView.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d));
        }
        String str = (String) ((androidx.navigation.internal.m) c3.g).f;
        TextView textView2 = c4047c.a;
        assistantMode.utils.studiableMetadata.b.x(textView2, str);
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) ((androidx.navigation.internal.m) c3.g).d;
        String str2 = (String) kVar.e;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2) && (oTConfiguration = this.a) != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str2)) != null) {
            textView2.setTypeface(otTypeFaceMap);
        } else {
            int iA = com.google.android.gms.cloudmessaging.k.a(textView2, kVar.b);
            textView2.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView2.getTypeface(), iA));
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.g.length() + 3;
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x0154 A[Catch: Exception -> 0x0035, TryCatch #0 {Exception -> 0x0035, blocks: (B:3:0x0012, B:6:0x0026, B:13:0x0041, B:14:0x0046, B:16:0x005f, B:20:0x0067, B:22:0x0076, B:25:0x0098, B:27:0x009e, B:33:0x00c6, B:49:0x0146, B:51:0x0154, B:28:0x00a2, B:30:0x00b2, B:32:0x00c3, B:31:0x00bb, B:54:0x0165, B:35:0x00d8, B:37:0x00e7, B:40:0x0108, B:42:0x010e, B:48:0x0136, B:43:0x0112, B:45:0x0122, B:47:0x0133, B:46:0x012b), top: B:58:0x0012 }] */
    /* JADX WARN: Removed duplicated region for block: B:61:? A[RETURN, SYNTHETIC] */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onBindViewHolder(androidx.recyclerview.widget.F0 r17, int r18) {
        /*
            Method dump skipped, instructions count: 370
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.adapter.C4048d.onBindViewHolder(androidx.recyclerview.widget.F0, int):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new C4047c(Z.c(viewGroup, R.layout.ot_iab_illustration_details_purpose_item, viewGroup, false));
    }
}
