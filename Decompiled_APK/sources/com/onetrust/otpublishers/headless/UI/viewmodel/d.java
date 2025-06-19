package com.onetrust.otpublishers.headless.UI.viewmodel;

import android.app.Application;
import androidx.compose.foundation.text.z0;
import androidx.lifecycle.AbstractC1237a;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3657k4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3665l4;
import com.onetrust.otpublishers.headless.Internal.Helper.g;
import com.onetrust.otpublishers.headless.Internal.Helper.j;
import com.onetrust.otpublishers.headless.Internal.Helper.s;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.UI.DataModels.h;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C4933y;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class d extends AbstractC1237a {
    public final com.onetrust.otpublishers.headless.Internal.Preferences.e c;
    public OTPublishersHeadlessSDK d;
    public boolean e;
    public String f;
    public String g;
    public String h;
    public boolean i;
    public String j;
    public String k;
    public final g l;
    public final s m;
    public final ArrayList n;
    public final LinkedHashMap o;
    public String[] p;
    public final Y q;
    public final Y r;
    public final Y s;
    public final Y t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Application application, com.onetrust.otpublishers.headless.Internal.Preferences.e otSharedPreferenceUtils) {
        super(application);
        Intrinsics.checkNotNullParameter(application, "application");
        Intrinsics.checkNotNullParameter(otSharedPreferenceUtils, "otSharedPreferenceUtils");
        this.c = otSharedPreferenceUtils;
        this.e = true;
        this.k = "";
        this.l = new g(A());
        this.m = new s(A());
        this.n = new ArrayList();
        this.o = new LinkedHashMap();
        this.p = new String[0];
        K k = K.a;
        this.q = new Y(k);
        this.r = new Y(k);
        this.s = new Y();
        this.t = new Y();
    }

    public final void B() {
        JSONObject preferenceCenterData;
        Application applicationA = A();
        new com.onetrust.otpublishers.headless.Internal.Preferences.d(applicationA);
        new com.onetrust.otpublishers.headless.Internal.Preferences.e(applicationA);
        new com.onetrust.otpublishers.headless.Internal.Models.b(applicationA);
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.d;
        if (oTPublishersHeadlessSDK != null && (preferenceCenterData = oTPublishersHeadlessSDK.getPreferenceCenterData()) != null) {
            JSONArray jSONArray = new JSONArray();
            Intrinsics.checkNotNullParameter(preferenceCenterData, "<this>");
            Intrinsics.checkNotNullParameter("Groups", "key");
            Intrinsics.checkNotNullParameter(jSONArray, "default");
            try {
                JSONArray jSONArray2 = preferenceCenterData.getJSONArray("Groups");
                Intrinsics.checkNotNullExpressionValue(jSONArray2, "{\n        getJSONArray(key)\n    }");
                jSONArray = jSONArray2;
            } catch (Exception unused) {
            }
            if (jSONArray != null) {
                JSONArray jSONArrayA = j.a(jSONArray, (List) AbstractC3665l4.a(this.q));
                z0 getSdkConsentStatus = new z0(1, this, d.class, "getConsentStatus", "getConsentStatus(Ljava/lang/String;)I", 0, 5);
                Intrinsics.checkNotNullParameter(getSdkConsentStatus, "getSdkConsentStatus");
                ArrayList arrayList = new ArrayList();
                int length = jSONArrayA.length();
                for (int i = 0; i < length; i++) {
                    JSONObject jSONObject = jSONArrayA.getJSONObject(i);
                    Intrinsics.checkNotNullExpressionValue(jSONObject, "getJSONObject(i)");
                    String strB = AbstractC3657k4.b(jSONObject, "SdkId", "-1");
                    int iIntValue = ((Number) getSdkConsentStatus.invoke(strB)).intValue();
                    arrayList.add(new com.onetrust.otpublishers.headless.UI.DataModels.g(strB, AbstractC3657k4.b(jSONObject, "Name", ""), AbstractC3657k4.a("Description", jSONObject), iIntValue != 0 ? iIntValue != 1 ? h.c : h.a : h.b));
                }
                Y y = this.r;
                if (this.k.length() > 0) {
                    ArrayList arrayList2 = new ArrayList();
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        Object next = it2.next();
                        if (StringsKt.G(((com.onetrust.otpublishers.headless.UI.DataModels.g) next).b, this.k, true)) {
                            arrayList2.add(next);
                        }
                    }
                    arrayList = arrayList2;
                }
                y.l(arrayList);
                D();
            }
        }
    }

    public final boolean C() {
        List listP;
        Y y = this.q;
        Collection collection = (Collection) y.d();
        if (collection == null || collection.isEmpty()) {
            listP = C4933y.P(this.p);
        } else {
            Object objD = y.d();
            Intrinsics.d(objD);
            Intrinsics.checkNotNullExpressionValue(objD, "{\n            _selectedC…egories.value!!\n        }");
            listP = (List) objD;
        }
        int size = listP.size();
        for (int i = 0; i < size; i++) {
            if (!this.c.g((String) listP.get(i))) {
                return true;
            }
        }
        return false;
    }

    public final void D() {
        boolean z;
        Y y = this.t;
        Object objA = AbstractC3665l4.a(this.r);
        Intrinsics.checkNotNullExpressionValue(objA, "_sdkItems.requireValue()");
        Iterable iterable = (Iterable) objA;
        if ((iterable instanceof Collection) && ((Collection) iterable).isEmpty()) {
            z = false;
        } else {
            Iterator it2 = iterable.iterator();
            while (it2.hasNext()) {
                if (((com.onetrust.otpublishers.headless.UI.DataModels.g) it2.next()).d == h.b) {
                    z = true;
                    break;
                }
            }
            z = false;
        }
        y.l(Boolean.valueOf(!z));
    }
}
