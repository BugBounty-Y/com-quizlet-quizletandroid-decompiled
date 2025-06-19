package com.google.mlkit.common.sdkinternal;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import androidx.camera.camera2.internal.c0;
import androidx.compose.animation.core.C0271v;
import androidx.core.view.InterfaceC1066x;
import com.facebook.internal.C1558m;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.W2;
import com.google.android.gms.internal.measurement.W3;
import com.google.android.gms.internal.measurement.Y3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.r;
import com.quizlet.data.model.C4181y;
import com.quizlet.db.data.models.persisted.DBBookmark;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.TreeSet;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b implements InterfaceC1066x, androidx.lifecycle.viewmodel.b, com.airbnb.lottie.animation.keyframe.b, r, com.google.firebase.crashlytics.internal.analytics.a, com.google.gson.internal.n, com.google.firebase.components.d, com.quizlet.local.ormlite.util.c {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static final float[] k() {
        float[] fArr = C0271v.s;
        if (fArr != null) {
            return fArr;
        }
        float[] fArr2 = new float[91];
        C0271v.s = fArr2;
        return fArr2;
    }

    public static C1558m m() {
        return new C1558m(null, V.e(new Pair(2, null), new Pair(4, null), new Pair(9, null), new Pair(17, null), new Pair(341, null)), V.e(new Pair(102, null), new Pair(190, null), new Pair(412, null)), null, null, null);
    }

    public static HashMap o(JSONObject jSONObject) {
        int iOptInt;
        HashSet hashSet;
        JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("items");
        if (jSONArrayOptJSONArray == null || jSONArrayOptJSONArray.length() == 0) {
            return null;
        }
        HashMap map = new HashMap();
        int length = jSONArrayOptJSONArray.length();
        for (int i = 0; i < length; i++) {
            JSONObject jSONObjectOptJSONObject = jSONArrayOptJSONArray.optJSONObject(i);
            if (jSONObjectOptJSONObject != null && (iOptInt = jSONObjectOptJSONObject.optInt("code")) != 0) {
                JSONArray jSONArrayOptJSONArray2 = jSONObjectOptJSONObject.optJSONArray("subcodes");
                if (jSONArrayOptJSONArray2 == null || jSONArrayOptJSONArray2.length() <= 0) {
                    hashSet = null;
                } else {
                    hashSet = new HashSet();
                    int length2 = jSONArrayOptJSONArray2.length();
                    for (int i2 = 0; i2 < length2; i2++) {
                        int iOptInt2 = jSONArrayOptJSONArray2.optInt(i2);
                        if (iOptInt2 != 0) {
                            hashSet.add(Integer.valueOf(iOptInt2));
                        }
                    }
                }
                map.put(Integer.valueOf(iOptInt), hashSet);
            }
        }
        return map;
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new TreeSet();
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public boolean a(float f) {
        throw new IllegalStateException("not implemented");
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public com.airbnb.lottie.value.a b() {
        throw new IllegalStateException("not implemented");
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public boolean c(float f) {
        return false;
    }

    @Override // androidx.core.view.InterfaceC1066x
    public void d(boolean z, int i, int i2, int i3) {
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public float e() {
        return 1.0f;
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new i((Context) c0Var.get(Context.class));
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public Object h(Object obj) {
        DBBookmark local = (DBBookmark) obj;
        Intrinsics.checkNotNullParameter(local, "local");
        return new C4181y(local.getLocalId(), local.getPersonId(), local.getFolderId(), local.getDeleted(), local.getLastModified());
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public float i() {
        return DefinitionKt.NO_Float_VALUE;
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public boolean isEmpty() {
        return true;
    }

    @Override // androidx.core.view.InterfaceC1066x
    public void j(int i, int i2, int i3, int i4) {
    }

    public synchronized C1558m l() {
        C1558m c1558m;
        try {
            if (C1558m.e == null) {
                C1558m.e = m();
            }
            c1558m = C1558m.e;
            Intrinsics.e(c1558m, "null cannot be cast to non-null type com.facebook.internal.FacebookRequestErrorClassification");
        } catch (Throwable th) {
            throw th;
        }
        return c1558m;
    }

    @Override // com.google.firebase.crashlytics.internal.analytics.a
    public void n(Bundle bundle) {
        Log.isLoggable("FirebaseCrashlytics", 3);
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.o0.b()).longValue());
            case 11:
                List list2 = AbstractC3893t.a;
                W3.b.get();
                Boolean bool = (Boolean) Y3.d.b();
                bool.getClass();
                return bool;
            case 12:
                Boolean bool2 = (Boolean) W2.c.b();
                bool2.getClass();
                return bool2;
            case 13:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.l.b();
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.c0.b();
                l.getClass();
                return l;
            case 15:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.k.b();
                l2.getClass();
                return l2;
            case 16:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.d.b()).longValue());
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.g0.b()).longValue());
        }
    }
}
