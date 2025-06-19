package com.facebook.appevents.cloudbridge;

import com.facebook.internal.A;
import com.facebook.y;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import kotlin.collections.a0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class h {
    public static final HashSet a = a0.c(200, 202);
    public static final HashSet b = a0.c(503, 504, 429);
    public static g c;
    public static List d;
    public static int e;

    public static final void a(String datasetID, String url, String accessKey) {
        Intrinsics.checkNotNullParameter(datasetID, "datasetID");
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(accessKey, "accessKey");
        com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
        com.google.mlkit.common.sdkinternal.model.a.w(y.d, "CAPITransformerWebRequests", " \n\nCloudbridge Configured: \n================\ndatasetID: %s\nurl: %s\naccessKey: %s\n\n", datasetID, url, accessKey);
        g gVar = new g(datasetID, url, accessKey);
        Intrinsics.checkNotNullParameter(gVar, "<set-?>");
        c = gVar;
        ArrayList arrayList = new ArrayList();
        Intrinsics.checkNotNullParameter(arrayList, "<set-?>");
        d = arrayList;
    }

    public static List b() {
        List list = d;
        if (list != null) {
            return list;
        }
        Intrinsics.m("transformedEvents");
        throw null;
    }
}
