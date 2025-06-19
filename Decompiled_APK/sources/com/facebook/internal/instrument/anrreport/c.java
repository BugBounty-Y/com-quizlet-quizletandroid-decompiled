package com.facebook.internal.instrument.anrreport;

import androidx.camera.camera2.internal.a0;
import com.facebook.internal.H;
import com.facebook.internal.J;
import com.google.android.gms.internal.mlkit_vision_common.F2;
import com.google.android.gms.internal.mlkit_vision_common.G2;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.collections.CollectionsKt;
import kotlin.ranges.i;
import kotlin.ranges.l;
import org.json.JSONArray;

/* loaded from: classes.dex */
public abstract class c {
    public static final AtomicBoolean a = new AtomicBoolean(false);

    public static final void a() {
        File[] fileArrListFiles;
        if (com.facebook.internal.instrument.crashshield.a.b(c.class)) {
            return;
        }
        try {
            if (J.B()) {
                return;
            }
            File fileD = G2.d();
            if (fileD == null) {
                fileArrListFiles = new File[0];
            } else {
                fileArrListFiles = fileD.listFiles(new H(2));
                if (fileArrListFiles == null) {
                    fileArrListFiles = new File[0];
                }
            }
            ArrayList arrayList = new ArrayList(fileArrListFiles.length);
            for (File file : fileArrListFiles) {
                arrayList.add(F2.d(file));
            }
            ArrayList arrayList2 = new ArrayList();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                Object next = it2.next();
                if (((com.facebook.internal.instrument.c) next).a()) {
                    arrayList2.add(next);
                }
            }
            List listN0 = CollectionsKt.n0(arrayList2, new a0(11));
            JSONArray jSONArray = new JSONArray();
            i it3 = l.h(0, Math.min(listN0.size(), 5)).iterator();
            while (it3.c) {
                jSONArray.put(listN0.get(it3.nextInt()));
            }
            G2.h("anr_reports", jSONArray, new b(listN0, 0));
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(c.class, th);
        }
    }
}
