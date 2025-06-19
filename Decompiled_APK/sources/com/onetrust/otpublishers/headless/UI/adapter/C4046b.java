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
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.quizlet.quizletandroid.R;
import org.json.JSONArray;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4046b extends AbstractC1361d0 {
    public final OTConfiguration a;
    public final String b;
    public final int c;
    public final C3 d;
    public final String e;
    public final Context f;
    public final com.onetrust.otpublishers.headless.UI.mobiledatautils.b g;
    public final JSONArray h;
    public final String i;
    public final C3 j;
    public final String k = OTVendorListMode.GENERAL;

    public C4046b(Context context, JSONArray jSONArray, String str, C3 c3, OTConfiguration oTConfiguration, String str2, int i, C3 c32, String str3, com.onetrust.otpublishers.headless.UI.mobiledatautils.b bVar) {
        this.f = context;
        this.h = jSONArray;
        this.i = str;
        this.j = c3;
        this.a = oTConfiguration;
        this.b = str2;
        this.c = i;
        this.d = c32;
        this.e = str3;
        this.g = bVar;
    }

    public final void d(C4045a c4045a) throws NumberFormatException {
        OTConfiguration oTConfiguration;
        Typeface otTypeFaceMap;
        C3 c3 = this.j;
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) c3.g;
        TextView textView = c4045a.a;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d)) {
            textView.setTextSize(Float.parseFloat((String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d));
        }
        String str = (String) ((androidx.navigation.internal.m) c3.g).f;
        TextView textView2 = c4045a.a;
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
        return this.h.length() + 3;
    }

    /* JADX WARN: Removed duplicated region for block: B:59:0x0172 A[Catch: Exception -> 0x002f, TryCatch #0 {Exception -> 0x002f, blocks: (B:3:0x000c, B:6:0x0020, B:12:0x0037, B:16:0x0046, B:18:0x0061, B:20:0x0065, B:21:0x0073, B:22:0x0076, B:24:0x007a, B:28:0x0082, B:30:0x0091, B:33:0x00b4, B:35:0x00ba, B:41:0x00e2, B:57:0x0164, B:59:0x0172, B:36:0x00be, B:38:0x00ce, B:40:0x00df, B:39:0x00d7, B:62:0x0183, B:43:0x00f5, B:45:0x0104, B:48:0x0126, B:50:0x012c, B:56:0x0154, B:51:0x0130, B:53:0x0140, B:55:0x0151, B:54:0x0149), top: B:66:0x000c }] */
    /* JADX WARN: Removed duplicated region for block: B:72:? A[RETURN, SYNTHETIC] */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onBindViewHolder(androidx.recyclerview.widget.F0 r13, int r14) {
        /*
            Method dump skipped, instructions count: 400
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.adapter.C4046b.onBindViewHolder(androidx.recyclerview.widget.F0, int):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new C4045a(Z.c(viewGroup, R.layout.ot_general_vendor_details_purpose_item, viewGroup, false));
    }
}
