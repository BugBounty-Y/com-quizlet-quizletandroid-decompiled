package com.google.mlkit.common.sdkinternal;

import android.content.Context;
import android.content.Intent;
import android.text.TextUtils;
import androidx.appcompat.widget.C0122z;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.moduleinstall.ModuleInstallResponse;
import com.google.android.gms.common.moduleinstall.internal.ApiFeatureRequest;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class h {
    public static final Feature[] a = new Feature[0];
    public static final Feature b;
    public static final Feature c;
    public static final Feature d;
    public static final Feature e;
    public static final com.google.android.gms.internal.mlkit_common.l f;
    public static final com.google.android.gms.internal.mlkit_common.l g;

    static {
        Feature feature = new Feature("vision.barcode", 1L);
        b = feature;
        Feature feature2 = new Feature("vision.custom.ica", 1L);
        Feature feature3 = new Feature("vision.face", 1L);
        Feature feature4 = new Feature("vision.ica", 1L);
        Feature feature5 = new Feature("vision.ocr", 1L);
        Feature feature6 = new Feature("mlkit.langid", 1L);
        Feature feature7 = new Feature("mlkit.nlclassifier", 1L);
        Feature feature8 = new Feature("tflite_dynamite", 1L);
        Feature feature9 = new Feature("mlkit.barcode.ui", 1L);
        Feature feature10 = new Feature("mlkit.smartreply", 1L);
        c = new Feature("mlkit.docscan.ui", 1L);
        d = new Feature("mlkit.docscan.stain", 1L);
        e = new Feature("mlkit.docscan.shadow", 1L);
        C0122z c0122z = new C0122z(13, (byte) 0);
        c0122z.y("barcode", feature);
        c0122z.y("custom_ica", feature2);
        c0122z.y("face", feature3);
        c0122z.y("ica", feature4);
        c0122z.y("ocr", feature5);
        c0122z.y("langid", feature6);
        c0122z.y("nlclassifier", feature7);
        c0122z.y("tflite_dynamite", feature8);
        c0122z.y("barcode_ui", feature9);
        c0122z.y("smart_reply", feature10);
        com.google.android.gms.internal.mlkit_common.e eVar = (com.google.android.gms.internal.mlkit_common.e) c0122z.d;
        if (eVar != null) {
            throw eVar.a();
        }
        com.google.android.gms.internal.mlkit_common.l lVarA = com.google.android.gms.internal.mlkit_common.l.a(c0122z.b, (Object[]) c0122z.c, c0122z);
        com.google.android.gms.internal.mlkit_common.e eVar2 = (com.google.android.gms.internal.mlkit_common.e) c0122z.d;
        if (eVar2 != null) {
            throw eVar2.a();
        }
        f = lVarA;
        C0122z c0122z2 = new C0122z(13, (byte) 0);
        c0122z2.y("com.google.android.gms.vision.barcode", feature);
        c0122z2.y("com.google.android.gms.vision.custom.ica", feature2);
        c0122z2.y("com.google.android.gms.vision.face", feature3);
        c0122z2.y("com.google.android.gms.vision.ica", feature4);
        c0122z2.y("com.google.android.gms.vision.ocr", feature5);
        c0122z2.y("com.google.android.gms.mlkit.langid", feature6);
        c0122z2.y("com.google.android.gms.mlkit.nlclassifier", feature7);
        c0122z2.y("com.google.android.gms.tflite_dynamite", feature8);
        c0122z2.y("com.google.android.gms.mlkit_smartreply", feature10);
        com.google.android.gms.internal.mlkit_common.e eVar3 = (com.google.android.gms.internal.mlkit_common.e) c0122z2.d;
        if (eVar3 != null) {
            throw eVar3.a();
        }
        com.google.android.gms.internal.mlkit_common.l lVarA2 = com.google.android.gms.internal.mlkit_common.l.a(c0122z2.b, (Object[]) c0122z2.c, c0122z2);
        com.google.android.gms.internal.mlkit_common.e eVar4 = (com.google.android.gms.internal.mlkit_common.e) c0122z2.d;
        if (eVar4 != null) {
            throw eVar4.a();
        }
        g = lVarA2;
    }

    public static void a(Context context, List list) {
        com.google.android.gms.common.c.b.getClass();
        if (com.google.android.gms.common.c.a(context) >= 221500000) {
            b(context, c(f, list));
            return;
        }
        Intent intent = new Intent();
        intent.setClassName("com.google.android.gms", "com.google.android.gms.vision.DependencyBroadcastReceiverProxy");
        intent.setAction("com.google.android.gms.vision.DEPENDENCY");
        intent.putExtra("com.google.android.gms.vision.DEPENDENCIES", TextUtils.join(",", list));
        intent.putExtra("requester_app_package", context.getApplicationInfo().packageName);
        context.sendBroadcast(intent);
    }

    public static void b(Context context, Feature[] featureArr) {
        com.google.android.gms.tasks.m mVarC;
        ArrayList arrayList = new ArrayList();
        arrayList.add(new n(featureArr, 0));
        u.a("APIs must not be empty.", !arrayList.isEmpty());
        com.google.android.gms.common.moduleinstall.internal.d dVar = new com.google.android.gms.common.moduleinstall.internal.d(context);
        ApiFeatureRequest apiFeatureRequestA = ApiFeatureRequest.a(arrayList, true);
        if (apiFeatureRequestA.a.isEmpty()) {
            mVarC = S3.i(new ModuleInstallResponse(0, false));
        } else {
            com.google.android.gms.common.api.internal.k kVarA = AbstractC2027eu.a();
            kVarA.e = new Feature[]{com.google.android.gms.internal.base.b.c};
            kVarA.c = true;
            kVarA.b = 27304;
            kVarA.d = new com.google.android.gms.auth.api.signin.internal.h(dVar, apiFeatureRequestA);
            mVarC = dVar.c(0, kVarA.a());
        }
        mVarC.o(new com.google.firebase.perf.logging.b(20));
    }

    public static Feature[] c(com.google.android.gms.internal.mlkit_common.l lVar, List list) {
        Feature[] featureArr = new Feature[list.size()];
        for (int i = 0; i < list.size(); i++) {
            Feature feature = (Feature) lVar.get(list.get(i));
            u.h(feature);
            featureArr[i] = feature;
        }
        return featureArr;
    }
}
